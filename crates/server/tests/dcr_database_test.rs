use aegaeon_server::client_registry::RegisteredClient;
use aegaeon_server::dcr_persistence::{
    create_dynamic_registration, delete_dynamic_registration, load_dynamic_registration_by_token,
    preflight_dynamic_registration_schema, registration_access_token_hash,
    update_dynamic_registration, DcrClientSecretChange,
};
use aegaeon_server::management::types::PolicyDocument;
use serde_json::json;
use sqlx::PgPool;
use std::fmt::Display;
use uuid::Uuid;

type TestResult = Result<(), String>;

trait TestContext<T> {
    fn test_context(self, context: &str) -> Result<T, String>;
}

impl<T, E: Display> TestContext<T> for Result<T, E> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.map_err(|err| format!("{context}: {err}"))
    }
}

impl<T> TestContext<T> for Option<T> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.ok_or_else(|| context.to_string())
    }
}

struct TestDcrEnvironment {
    team_id: Uuid,
    tenant_id: Uuid,
    environment_id: Uuid,
    issuer_host: String,
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_dynamic_registration_lifecycle_hashes_and_hydrates() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool)
        .await
        .test_context("test DCR environment")?;
    let result = dynamic_registration_lifecycle(&pool, &env).await;
    let cleanup_result = cleanup_test_dcr_environment(&pool, &env)
        .await
        .test_context("cleanup DCR test environment");
    match (result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_err)) => Err(cleanup_err),
        (Err(test_err), Ok(())) => Err(test_err),
        (Err(test_err), Err(cleanup_err)) => {
            Err(format!("{test_err}; cleanup failed: {cleanup_err}"))
        }
    }
}

async fn dynamic_registration_lifecycle(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let client = sample_registered_client("pg-dcr-client", Some("plain-client-secret"));
    let response_types = vec!["code".to_string()];

    preflight_dynamic_registration_schema(pool)
        .await
        .test_context("DCR schema preflight")?;
    create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &response_types,
        "registration-token-a",
        "test-dcr-create",
    )
    .await
    .test_context("create dynamic registration")?;

    let token_hash = stored_registration_token_hash(pool, env.environment_id, &client.client_id)
        .await
        .test_context("stored registration token hash")?;
    assert_eq!(
        token_hash,
        registration_access_token_hash("registration-token-a")
    );
    assert_ne!(token_hash, "registration-token-a");

    let stored = load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        &client.client_id,
        "registration-token-a",
    )
    .await
    .test_context("load dynamic registration")?
    .test_context("stored dynamic registration")?;
    assert_eq!(stored.client.client_id, client.client_id);
    assert!(stored.client.client_secret.is_none());
    assert!(stored.has_active_client_secret);
    assert_eq!(
        active_client_secret_count(pool, env.environment_id).await?,
        1
    );

    let updated = sample_registered_client(&client.client_id, None);
    update_dynamic_registration(
        pool,
        &stored,
        &updated,
        &response_types,
        "registration-token-b",
        DcrClientSecretChange::RevokeAll,
        "test-dcr-update",
    )
    .await
    .test_context("update dynamic registration")?;
    assert!(
        load_dynamic_registration_by_token(
            pool,
            &env.issuer_host,
            &client.client_id,
            "registration-token-a",
        )
        .await
        .test_context("load old dynamic registration token")?
        .is_none(),
        "rotated registration token must invalidate the old hash"
    );
    let updated_stored = load_dynamic_registration_by_token(
        pool,
        &env.issuer_host,
        &client.client_id,
        "registration-token-b",
    )
    .await
    .test_context("load rotated dynamic registration token")?
    .test_context("updated dynamic registration")?;
    assert_eq!(updated_stored.client.token_endpoint_auth_method, "none");
    assert!(!updated_stored.has_active_client_secret);
    assert_eq!(
        active_client_secret_count(pool, env.environment_id).await?,
        0
    );

    delete_dynamic_registration(pool, &updated_stored, "test-dcr-delete")
        .await
        .test_context("delete dynamic registration")?;
    assert!(
        load_dynamic_registration_by_token(
            pool,
            &env.issuer_host,
            &client.client_id,
            "registration-token-b",
        )
        .await
        .test_context("load deleted dynamic registration")?
        .is_none(),
        "deleted dynamic registration must not authenticate"
    );
    Ok(())
}

async fn test_pg_pool() -> Result<Option<PgPool>, String> {
    let url = match std::env::var("AEGAEON_DATABASE_URL") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("AEGAEON_DATABASE_URL must be valid Unicode".to_string());
        }
    };
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .map(Some)
        .map_err(|err| format!("failed to connect AEGAEON_DATABASE_URL-backed Postgres: {err}"))
}

async fn setup_test_dcr_environment(pool: &PgPool) -> Result<TestDcrEnvironment, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let team_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let environment_id = Uuid::new_v4();
    let configuration_version_id = Uuid::new_v4();
    let suffix = &environment_id.to_string()[..8];
    let team_slug = format!("dcrteam{suffix}");
    let tenant_slug = format!("dcrtenant{suffix}");
    let environment_slug = format!("dcrenv{suffix}");
    let issuer_host = format!("{environment_slug}.test.example.com");
    let issuer_url = format!("https://{issuer_host}");
    let configuration_document = json!({
        "schemaVersion": 1,
        "issuerHost": issuer_host,
        "issuerUrl": issuer_url,
        "policy": PolicyDocument::default(),
        "scopeAllowlist": [],
        "keyStore": {
            "type": "databaseEncrypted",
            "configuration": {},
            "redacted": true
        }
    });

    sqlx::query("INSERT INTO aegaeon.teams (id, name, slug) VALUES ($1, $2, $3)")
        .bind(team_id)
        .bind(&team_slug)
        .bind(&team_slug)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r"
INSERT INTO aegaeon.tenants (id, team_id, slug, name, region)
VALUES ($1, $2, $3, $4, 'test')
        ",
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(&tenant_slug)
    .bind(&tenant_slug)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r"
INSERT INTO aegaeon.environments (id, tenant_id, name, slug, issuer_host)
VALUES ($1, $2, $3, $4, $5)
        ",
    )
    .bind(environment_id)
    .bind(tenant_id)
    .bind(&environment_slug)
    .bind(&environment_slug)
    .bind(&issuer_host)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r"
INSERT INTO aegaeon.configuration_versions (
  id,
  environment_id,
  version_number,
  configuration_hash,
  status,
  configuration_document
)
VALUES ($1, $2, 1, $3, 'ACTIVE', $4)
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .bind(format!("test-{suffix}"))
    .bind(configuration_document)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r"
UPDATE aegaeon.environments
SET active_configuration_version_id = $1
WHERE id = $2
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(TestDcrEnvironment {
        team_id,
        tenant_id,
        environment_id,
        issuer_host,
    })
}

async fn cleanup_test_dcr_environment(
    pool: &PgPool,
    env: &TestDcrEnvironment,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for sql in [
        "DELETE FROM aegaeon.audit_events WHERE environment_id = $1",
        "DELETE FROM aegaeon.client_secrets WHERE environment_id = $1",
        "DELETE FROM aegaeon.dynamic_client_registrations WHERE environment_id = $1",
        "DELETE FROM aegaeon.clients WHERE environment_id = $1",
    ] {
        sqlx::query(sql)
            .bind(env.environment_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "UPDATE aegaeon.environments SET active_configuration_version_id = NULL WHERE id = $1",
    )
    .bind(env.environment_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM aegaeon.configuration_versions WHERE environment_id = $1")
        .bind(env.environment_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM aegaeon.environments WHERE id = $1")
        .bind(env.environment_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM aegaeon.tenants WHERE id = $1")
        .bind(env.tenant_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM aegaeon.teams WHERE id = $1")
        .bind(env.team_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await
}

fn sample_registered_client(client_id: &str, client_secret: Option<&str>) -> RegisteredClient {
    let token_endpoint_auth_method = client_secret.map_or("none", |_| "client_secret_basic");
    RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: client_secret.map(ToString::to_string),
        redirect_uris: vec!["https://client.example.com/callback".to_string()],
        post_logout_redirect_uris: vec!["https://client.example.com/logout".to_string()],
        backchannel_logout_uri: Some("https://client.example.com/backchannel-logout".to_string()),
        backchannel_logout_session_required: true,
        token_endpoint_auth_method: token_endpoint_auth_method.to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
        allowed_grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        registration_access_token: None,
        client_id_issued_at: Some(1_700_000_000),
    }
}

async fn stored_registration_token_hash(
    pool: &PgPool,
    environment_id: Uuid,
    client_identifier: &str,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(
        r"
SELECT registration_access_token_hash
FROM aegaeon.dynamic_client_registrations
WHERE environment_id = $1
  AND client_identifier = $2
        ",
    )
    .bind(environment_id)
    .bind(client_identifier)
    .fetch_one(pool)
    .await
}

async fn active_client_secret_count(pool: &PgPool, environment_id: Uuid) -> Result<i64, String> {
    sqlx::query_scalar(
        r"
SELECT COUNT(*)
FROM aegaeon.client_secrets
WHERE environment_id = $1
  AND status = 'ACTIVE'
        ",
    )
    .bind(environment_id)
    .fetch_one(pool)
    .await
    .test_context("active client secret count")
}
