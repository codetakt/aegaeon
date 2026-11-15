//! Owned disposable predecessor/current databases; no shared schema mutation.
mod migration;
mod router;
use super::*;
use crate::client_registry::RegisteredClientJwks;
use crate::test_utils::jwk_usage::material;
use crate::test_utils::postgres_cleanup::{
    close_pool, finish_database, quote_database_identifier, wait_database_idle,
};
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
    let name = format!("aegaeon_jwks_upgrade_{}", Uuid::new_v4().simple());
    run_public_fixture(&name, PgPoolOptions::new().max_connections(4)).await
}

#[derive(Debug, thiserror::Error)]
#[error("{initial}; additional public-JWKS fixture cleanup failure: {cleanup}")]
struct PublicFixtureCleanupError {
    #[source]
    initial: Box<dyn std::error::Error>,
    cleanup: sqlx::Error,
}

fn finish_public_fixture(result: TestResult, cleanup: Result<(), sqlx::Error>) -> TestResult {
    match (result, cleanup) {
        (Err(initial), Err(cleanup)) => {
            Err(Box::new(PublicFixtureCleanupError { initial, cleanup }))
        }
        (result, cleanup) => finish_test(result, cleanup),
    }
}

async fn run_public_fixture(name: &str, pool_options: PgPoolOptions) -> TestResult {
    let limit = std::time::Duration::from_secs(5);
    let url = std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?;
    let options = PgConnectOptions::from_str(&url)?.application_name(name);
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(limit)
        .connect_with(options.clone())
        .await?;
    let created: TestResult = async {
        tokio::time::timeout(
            limit,
            sqlx::query(&format!(
                "CREATE DATABASE {}",
                quote_database_identifier(name),
            ))
            .execute(&admin),
        )
        .await??;
        Ok(())
    }
    .await;
    if created.is_err() {
        // An unacknowledged CREATE never authorizes removing an existing DB.
        return finish_public_fixture(created, close_pool(&admin, limit).await);
    }
    // Keep the pool handle across a failed first connection so cleanup can drain it.
    let pool = pool_options.connect_lazy_with(options.database(name));
    let result: TestResult = async {
        let connection = tokio::time::timeout(limit, pool.acquire()).await??;
        drop(connection);
        // A live owned connection is a negative control for the cleanup observer.
        let mut live_observations = Vec::new();
        if tokio::time::timeout(
            std::time::Duration::from_millis(30),
            wait_database_idle(&admin, name, &mut live_observations),
        )
        .await
        .is_ok()
        {
            return Err(
                io::Error::other("owned backend did not block the cleanup observer").into(),
            );
        }
        migration::scenario(&pool).await
    }
    .await;
    let cleanup = finish_database(&admin, &pool, name, limit).await;
    finish_public_fixture(result, cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; failed public-JWKS connection must remove the owned database"]
async fn public_client_jwks_failed_connection_removes_database() -> TestResult {
    use sqlx::{Connection, PgConnection};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let mut observer =
        PgConnection::connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?).await?;
    let name = format!("aegaeon_jwks_upgrade_{}", Uuid::new_v4().simple());
    let rejected = Arc::new(AtomicBool::new(false));
    let options = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(500))
        .after_connect({
            let rejected = rejected.clone();
            move |connection, _| {
                let rejected = rejected.clone();
                Box::pin(async move {
                    let result = sqlx::query("SELECT missing_public_jwks_fixture_column")
                        .execute(connection)
                        .await;
                    if let Err(sqlx::Error::Database(error)) = &result {
                        rejected.store(error.code().as_deref() == Some("42703"), Ordering::SeqCst);
                    }
                    result.map(|_| ())
                })
            }
        });
    let result: TestResult = async {
        let error = run_public_fixture(&name, options)
            .await
            .err()
            .ok_or_else(|| io::Error::other("connection unexpectedly succeeded"))?;
        if !rejected.load(Ordering::SeqCst)
            || !matches!(
                error.downcast_ref::<sqlx::Error>(),
                Some(sqlx::Error::PoolTimedOut)
            )
        {
            return Err(io::Error::other(format!(
                "original connection error was not retained: {error}"
            ))
            .into());
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let live: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name=$1)",
                )
                .bind(&name)
                .fetch_one(&mut observer)
                .await?;
                if !live {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
                    .bind(&name)
                    .fetch_one(&mut observer)
                    .await?;
            if exists {
                return Err(sqlx::Error::Protocol(
                    "public-JWKS connection failure leaked its database".into(),
                ));
            }
            Ok::<_, sqlx::Error>(())
        })
        .await??;
        Ok(())
    }
    .await;
    let cleanup = if rejected.load(Ordering::SeqCst) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            sqlx::query(&format!(
                "DROP DATABASE IF EXISTS {}",
                quote_database_identifier(&name)
            ))
            .execute(&mut observer)
            .await?;
            Ok::<_, sqlx::Error>(())
        })
        .await
        .map_err(|_| sqlx::Error::Protocol("public-JWKS independent recovery timed out".into()))
        .and_then(|r| r)
    } else {
        Ok(())
    };
    let close = tokio::time::timeout(std::time::Duration::from_secs(5), observer.close())
        .await
        .map_err(|_| sqlx::Error::Protocol("public-JWKS observer close timed out".into()))
        .and_then(|r| r);
    finish_public_fixture(finish_public_fixture(result, cleanup), close)
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
