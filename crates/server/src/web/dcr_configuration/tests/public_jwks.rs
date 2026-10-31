//! Owned disposable predecessor/current databases; no shared schema mutation.
mod migration;
mod router;
use super::*;
use crate::client_registry::RegisteredClientJwks;
use crate::test_utils::jwk_usage::material;
use jsonwebtoken::Algorithm;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    Row,
};
use std::str::FromStr;
use uuid::Uuid;

const UPGRADE: &str =
    include_str!("../../../../../../db/migrations/20261027010000_public_client_jwk_storage.sql");
const DRY_RUN: &str =
    include_str!("../../../../../../scripts/database/public-client-jwks-dry-run.sql");
const DESIRED: &str = include_str!("../../../../../../db/schema.sql");
const PREDECESSOR: &[&str] = &[
    include_str!("../../../../../../db/migrations/20260803140000_baseline.sql"),
    include_str!("../../../../../../db/migrations/20260909070000_authorization_consents.sql"),
    include_str!("../../../../../../db/migrations/20260909090000_authorization_logins.sql"),
    include_str!("../../../../../../db/migrations/20260909120000_token_exchange_policy.sql"),
    include_str!("../../../../../../db/migrations/20260911090000_application_authorizations.sql"),
    include_str!(
        "../../../../../../db/migrations/20260913090000_application_authorization_identities.sql"
    ),
    include_str!("../../../../../../db/migrations/20260930090000_client_credentials_policy.sql"),
    include_str!(
        "../../../../../../db/migrations/20261002100000_federation_entity_cache_expiration.sql"
    ),
    include_str!("../../../../../../db/migrations/20261012000000_logout_confirmations.sql"),
    include_str!("../../../../../../db/migrations/20261013090000_account_link_provenance.sql"),
    include_str!(
        "../../../../../../db/migrations/20261027000000_introspection_signing_key_slots.sql"
    ),
];

#[tokio::test]
#[ignore = "requires PostgreSQL with permission to create solely owned disposable databases"]
async fn public_client_jwks_upgrade_and_owner_repair() -> TestResult {
    let url = std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?;
    let options = PgConnectOptions::from_str(&url)?;
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone())
        .await?;
    let name = format!("aegaeon_jwks_upgrade_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options.database(&name))
        .await?;
    // A live owned connection is a negative control for the cleanup observer.
    let mut live_observations = Vec::new();
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(30),
        wait_database_idle(&admin, &name, &mut live_observations),
    )
    .await
    .is_err());
    let result = migration::scenario(&pool).await;
    pool.close().await;
    let mut observations = Vec::new();
    let cleanup: Result<(), sqlx::Error> = async {
        // Pool close completes local transport cleanup; PostgreSQL can still be
        // removing the corresponding backend. Observe this exact disposable DB.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            wait_database_idle(&admin, &name, &mut observations),
        )
        .await
        .map_err(|_| {
            sqlx::Error::Protocol(format!(
                "owned fixture backend exit deadline; observations={}",
                json!(observations)
            ))
        })??;
        sqlx::query(&format!("DROP DATABASE {name}"))
            .execute(&admin)
            .await?;
        Ok(())
    }
    .await;
    admin.close().await;
    finish_test(result, cleanup)
}

async fn wait_database_idle(
    admin: &PgPool,
    name: &str,
    observations: &mut Vec<Value>,
) -> Result<(), sqlx::Error> {
    let started = std::time::Instant::now();
    loop {
        // Only the exact disposable database, bounded rows, and no SQL text,
        // identifiers, passwords or other databases' session contents.
        let states: Value = sqlx::query_scalar(
            "SELECT COALESCE(jsonb_agg(to_jsonb(owned) ORDER BY pid),'[]'::jsonb) FROM (SELECT pid,state,wait_event_type,wait_event,backend_type,backend_start,state_change,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE datname=$1 ORDER BY pid LIMIT 8) owned",
        ).bind(name).fetch_one(admin).await?;
        let elapsed = started.elapsed().as_millis();
        let changed = observations
            .last()
            .is_none_or(|last| last["states"] != states);
        if changed
            || observations
                .last()
                .and_then(|last| last["elapsed_ms"].as_u64())
                .is_none_or(|last| elapsed.saturating_sub(u128::from(last)) >= 1000)
        {
            if observations.len() == 64 {
                observations.remove(0);
            }
            observations.push(json!({"elapsed_ms": elapsed, "states": states}));
        }
        if states.as_array().is_some_and(Vec::is_empty) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

fn public_set() -> Value {
    let (mut key, _) = material(Algorithm::RS256);
    key["extension"] = json!({"d":"nested-unchanged"});
    key["x5c"] = json!(["certificate-policy-unchanged"]);
    let mut second = key.clone();
    second["kid"] = json!("second-key");
    second["use"] = json!("enc");
    json!({"keys":[key,second],"extension":{"k":"set-unchanged"}})
}

async fn registration(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    id: &str,
    token: &str,
) -> TestResult {
    let mut client = sample_registered_client(id);
    if id == "inactive" {
        client.client_secret = Some("synthetic-owned-fixture-secret".into());
    }
    client.inline_jwks =
        Some(RegisteredClientJwks::from_value(public_set(), false).map_err(io::Error::other)?);
    // Seed retained rows before runtime schema admission. Production startup must
    // still wait for all pending migrations; the scenario checks that gate.
    create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        token,
        "offline-upgrade-fixture",
    )
    .await?;
    Ok(())
}

async fn set_jwks(pool: &PgPool, env: &TestDcrEnvironment, id: &str, value: &Value) -> TestResult {
    let result=sqlx::query("UPDATE aegaeon.dynamic_client_registrations SET jwks=$1 WHERE environment_id=$2 AND client_identifier=$3")
        .bind(value).bind(env.environment_id).bind(id).execute(pool).await?;
    assert_eq!(result.rows_affected(), 1);
    Ok(())
}

async fn stored_state(pool: &PgPool) -> TestResult<Value> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_object('registrations', (SELECT jsonb_agg(to_jsonb(r) ORDER BY environment_id, client_id) FROM aegaeon.dynamic_client_registrations r), 'clients',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM aegaeon.clients c),'secrets',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM aegaeon.client_secrets s),'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM aegaeon.audit_events a))")
        .fetch_one(pool).await?)
}
