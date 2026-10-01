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
    include_str!("../../../../../../db/migrations/20261002090000_public_client_jwk_storage.sql");
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
];

#[tokio::test]
#[ignore = "requires PostgreSQL with permission to create solely owned disposable databases"]
async fn public_client_jwks_upgrade_and_owner_repair() -> TestResult {
    let url = std::env::var("AEGAEON_DATABASE_URL")?;
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
    let result = migration::scenario(&pool).await;
    pool.close().await;
    let cleanup = sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&admin)
        .await
        .map(|_| ());
    admin.close().await;
    finish_test(result, cleanup)
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
    create_test_registration(pool, env, &client, token).await
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
