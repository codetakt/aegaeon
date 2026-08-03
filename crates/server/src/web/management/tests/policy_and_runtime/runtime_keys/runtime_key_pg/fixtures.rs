struct RuntimeKeyTestEnvironment {
    administrator_id: Uuid,
    non_member_administrator_id: Uuid,
    team_id: Uuid,
    tenant_id: Uuid,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    issuer_host: String,
}

async fn runtime_key_test_pg_pool() -> Result<Option<sqlx::PgPool>, Box<dyn StdError>> {
    let url = match std::env::var("AEGAEON_DATABASE_URL") {
        Ok(url) => url,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AEGAEON_DATABASE_URL must be valid Unicode",
            )
            .into());
        }
    };
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .map(Some)
        .map_err(|err| {
            io::Error::other(format!(
                "failed to connect AEGAEON_DATABASE_URL-backed Postgres: {err}"
            ))
            .into()
        })
}

fn finish_runtime_key_pg_test(result: TestResult, cleanup: Result<(), sqlx::Error>) -> TestResult {
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_err)) => Err(cleanup_err.into()),
        (Err(test_err), Ok(())) => Err(test_err),
        (Err(test_err), Err(cleanup_err)) => Err(io::Error::other(format!(
            "{test_err}; cleanup failed: {cleanup_err}"
        ))
        .into()),
    }
}

fn runtime_key_test_path(env: &RuntimeKeyTestEnvironment) -> TeamEnvironmentPath {
    TeamEnvironmentPath::for_tests(env.team_id, env.environment_id)
}

fn runtime_key_test_runtime_key_path(
    env: &RuntimeKeyTestEnvironment,
    runtime_key_id: Uuid,
) -> TeamEnvironmentRuntimeKeyPath {
    TeamEnvironmentRuntimeKeyPath::for_tests(env.team_id, env.environment_id, runtime_key_id)
}

fn dcr_bearer_token_management_path(env: &RuntimeKeyTestEnvironment) -> String {
    format!(
        "/api/v1/teams/{}/environments/{}/dcrBearerToken",
        env.team_id, env.environment_id
    )
}

fn management_cookie_header(session_id: Option<&str>, csrf_token: Option<&str>) -> Option<String> {
    let parts = [
        session_id.map(|sid| format!("{MGMT_SESSION_COOKIE_NAME}={sid}")),
        csrf_token.map(|token| format!("{CSRF_COOKIE_NAME}={token}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    (!parts.is_empty()).then(|| parts.join("; "))
}

fn dcr_bearer_token_management_request(
    method: Method,
    env: &RuntimeKeyTestEnvironment,
    session_id: Option<&str>,
    csrf_token: Option<&str>,
    json_body: Option<&str>,
) -> Result<Request<Body>, axum::http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(dcr_bearer_token_management_path(env))
        .header("x-request-id", "req-dcr-bearer-http")
        .header(header::ORIGIN, "https://admin.example.com");

    if let Some(cookie) = management_cookie_header(session_id, csrf_token) {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(token) = csrf_token {
        builder = builder.header("x-csrf-token", token);
    }
    if json_body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }

    builder.body(Body::from(json_body.unwrap_or("").to_string()))
}

async fn response_json(response: Response) -> Result<serde_json::Value, Box<dyn StdError>> {
    let bytes = body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn setup_runtime_key_test_environment(
    pool: &sqlx::PgPool,
) -> Result<RuntimeKeyTestEnvironment, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let administrator_id = Uuid::new_v4();
    let non_member_administrator_id = Uuid::new_v4();
    let team_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let environment_id = Uuid::new_v4();
    let configuration_version_id = Uuid::new_v4();
    let suffix = &environment_id.to_string()[..8];
    let team_slug = format!("rtkeyteam{suffix}");
    let tenant_slug = format!("rtkeytenant{suffix}");
    let environment_slug = format!("rtkeyenv{suffix}");
    let issuer_host = format!("{environment_slug}.test.example.com");
    let issuer_url = format!("https://{issuer_host}");
    let configuration_document = serde_json::json!({
        "schemaVersion": 1,
        "issuerHost": issuer_host,
        "issuerUrl": issuer_url,
        "policy": base_secure_policy(),
        "scopeAllowlist": ["openid"],
        "keyStore": {
            "type": "databaseEncrypted",
            "configuration": {},
            "redacted": true
        }
    });

    sqlx::query(
        "INSERT INTO aegaeon.administrators (id, email, password_hash) VALUES ($1, $2, $3)",
    )
    .bind(administrator_id)
    .bind(format!("rtkey-{suffix}@example.com"))
    .bind("test-password-hash")
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO aegaeon.administrators (id, email, password_hash) VALUES ($1, $2, $3)",
    )
    .bind(non_member_administrator_id)
    .bind(format!("rtkey-non-member-{suffix}@example.com"))
    .bind("test-password-hash")
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO aegaeon.teams (id, name, slug) VALUES ($1, $2, $3)")
        .bind(team_id)
        .bind(&team_slug)
        .bind(&team_slug)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
            "INSERT INTO aegaeon.team_memberships (team_id, administrator_id, role) VALUES ($1, $2, 'OWNER')",
        )
        .bind(team_id)
        .bind(administrator_id)
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
  configuration_document,
  created_by_administrator_id
)
VALUES ($1, $2, 1, $3, 'ACTIVE', $4, $5)
            ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .bind(format!("rtkey-test-{suffix}"))
    .bind(configuration_document)
    .bind(administrator_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE aegaeon.environments SET active_configuration_version_id = $1 WHERE id = $2",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r"
INSERT INTO aegaeon.environment_policies (
  environment_id,
  configuration_version_id,
  pkce_required,
  dcr_enabled,
  require_pushed_authorization_requests,
  allowed_signing_algorithms,
  allowed_grant_types,
  access_token_time_to_live_seconds,
  id_token_time_to_live_seconds,
  refresh_token_time_to_live_seconds,
  authorization_code_time_to_live_seconds,
  jose_header_max_len,
  upstream_auth_ttl_seconds,
  upstream_logout_relay_ttl_seconds,
  upstream_discovery_cache_ttl_seconds,
  upstream_jwks_cache_ttl_seconds,
  crypto_profile,
  authorization_details_types_supported,
  acr_values_supported,
  default_acr,
  local_password_acr
)
VALUES ($1, $2, true, false, false, $3, $4, 3600, 3600, 2592000, 300, 4096, 300, 300, 300, 300, 'verified', $5, $6, NULL, NULL)
            ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(vec![
        "RS256".to_string(),
        "EdDSA".to_string(),
    ])
    .bind(vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
        "client_credentials".to_string(),
    ])
    .bind(Vec::<String>::new())
    .bind(Vec::<String>::new())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(RuntimeKeyTestEnvironment {
        administrator_id,
        non_member_administrator_id,
        team_id,
        tenant_id,
        environment_id,
        configuration_version_id,
        issuer_host,
    })
}

async fn runtime_key_status(
    pool: &sqlx::PgPool,
    environment_id: Uuid,
    kid: &str,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(
        r"
SELECT status::text
FROM aegaeon.runtime_keys
WHERE environment_id = $1 AND kid = $2
            ",
    )
    .bind(environment_id)
    .bind(kid)
    .fetch_one(pool)
    .await
}

async fn runtime_key_retiring_expires_at(
    pool: &sqlx::PgPool,
    environment_id: Uuid,
    kid: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        r#"
SELECT to_char(retiring_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
FROM aegaeon.runtime_keys
WHERE environment_id = $1 AND kid = $2
            "#,
    )
    .bind(environment_id)
    .bind(kid)
    .fetch_one(pool)
    .await
}

async fn runtime_key_audit_payloads(
    pool: &sqlx::PgPool,
    environment_id: Uuid,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar(
        r"
SELECT jsonb_build_object('eventType', event_type, 'data', data)
FROM aegaeon.audit_events
WHERE environment_id = $1
  AND event_type LIKE 'management.runtimeKey.%'
ORDER BY occurred_at ASC, id ASC
            ",
    )
    .bind(environment_id)
    .fetch_all(pool)
    .await
}

async fn dcr_bearer_token_audit_payloads(
    pool: &sqlx::PgPool,
    environment_id: Uuid,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar(
        r"
SELECT jsonb_build_object('eventType', event_type, 'data', data)
FROM aegaeon.audit_events
WHERE environment_id = $1
  AND event_type LIKE 'management.dcrBearerToken.%'
ORDER BY occurred_at ASC, id ASC
            ",
    )
    .bind(environment_id)
    .fetch_all(pool)
    .await
}

async fn cleanup_runtime_key_test_environment(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for sql in [
        "DELETE FROM aegaeon.audit_events WHERE environment_id = $1",
        "DELETE FROM aegaeon.environment_dcr_bearer_tokens WHERE environment_id = $1",
        "DELETE FROM aegaeon.runtime_keys WHERE environment_id = $1",
        "DELETE FROM aegaeon.environment_policies WHERE environment_id = $1",
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
    sqlx::query(
        "DELETE FROM aegaeon.team_memberships WHERE team_id = $1 AND administrator_id = $2",
    )
    .bind(env.team_id)
    .bind(env.administrator_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM aegaeon.teams WHERE id = $1")
        .bind(env.team_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM aegaeon.administrators WHERE id IN ($1, $2)")
        .bind(env.administrator_id)
        .bind(env.non_member_administrator_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await
}
