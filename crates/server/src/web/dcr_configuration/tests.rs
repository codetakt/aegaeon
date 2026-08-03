use super::super::AppState;
use axum::{
    body::{self, Body},
    http::{header, Method, Request, StatusCode},
    response::Response,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{collections::HashSet, error::Error, io, sync::Arc, time::Duration};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    client_registry::{ClientRegistry, RegisteredClient},
    dcr_persistence::{create_dynamic_registration, preflight_dynamic_registration_schema},
    management::types::PolicyDocument,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct TestDcrEnvironment {
    team_id: Uuid,
    tenant_id: Uuid,
    environment_id: Uuid,
    issuer_host: String,
    issuer_url: String,
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn dcr_configuration_read_requires_matching_registration_token() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool).await?;
    let result = read_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn dcr_configuration_update_rotates_token_and_preserves_client_id() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool).await?;
    let result = update_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn dcr_configuration_delete_invalidates_registration() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool).await?;
    let result = delete_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn dcr_configuration_rejects_token_owned_by_another_client() -> TestResult {
    let Some(pool) = test_pg_pool().await? else {
        return Ok(());
    };
    let env = setup_test_dcr_environment(&pool).await?;
    let result = ownership_mismatch_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn read_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let client = sample_registered_client("dcr-read-client");
    create_test_registration(pool, env, &client, "read-token").await?;
    let app = test_router(pool, env).await?;

    let response = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some("read-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await?;
    assert_eq!(body["client_id"], client.client_id);
    assert_eq!(body["redirect_uris"], json!(client.redirect_uris));

    let missing = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            None,
            None,
        )?)
        .await?;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let mismatched = app
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some("wrong-token"),
            None,
        )?)
        .await?;
    assert_eq!(mismatched.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn update_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let client = sample_registered_client("dcr-update-client");
    create_test_registration(pool, env, &client, "old-token").await?;
    let app = test_router(pool, env).await?;
    let updated_redirect_uri = "https://updated.example.com/callback";
    let update = json!({
        "client_id": client.client_id,
        "redirect_uris": [updated_redirect_uri],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "scope": "openid",
        "pkce_required": true
    });

    let response = app
        .clone()
        .oneshot(registration_request(
            Method::PUT,
            &client.client_id,
            Some("old-token"),
            Some(&update),
        )?)
        .await?;
    let update_status = response.status();
    let body = response_json(response).await?;
    assert_eq!(update_status, StatusCode::OK, "DEBUG body: {body}");
    assert_eq!(body["client_id"], client.client_id);
    assert_eq!(body["redirect_uris"], json!([updated_redirect_uri]));
    let new_token = body["registration_access_token"]
        .as_str()
        .ok_or_else(|| io::Error::other("update response missing registration_access_token"))?;
    assert_ne!(new_token, "old-token");

    let old_token_response = app
        .clone()
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some("old-token"),
            None,
        )?)
        .await?;
    assert_eq!(old_token_response.status(), StatusCode::UNAUTHORIZED);

    let new_token_response = app
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some(new_token),
            None,
        )?)
        .await?;
    assert_eq!(new_token_response.status(), StatusCode::OK);
    let read_body = response_json(new_token_response).await?;
    assert_eq!(read_body["client_id"], client.client_id);
    assert_eq!(read_body["redirect_uris"], json!([updated_redirect_uri]));
    Ok(())
}

async fn delete_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let client = sample_registered_client("dcr-delete-client");
    create_test_registration(pool, env, &client, "delete-token").await?;
    let app = test_router(pool, env).await?;

    let response = app
        .clone()
        .oneshot(registration_request(
            Method::DELETE,
            &client.client_id,
            Some("delete-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let read_after_delete = app
        .oneshot(registration_request(
            Method::GET,
            &client.client_id,
            Some("delete-token"),
            None,
        )?)
        .await?;
    assert_eq!(read_after_delete.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn ownership_mismatch_scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let owner = sample_registered_client("dcr-owner-client");
    let other = sample_registered_client("dcr-other-client");
    create_test_registration(pool, env, &owner, "owner-token").await?;
    create_test_registration(pool, env, &other, "other-token").await?;
    let app = test_router(pool, env).await?;

    let response = app
        .oneshot(registration_request(
            Method::GET,
            &other.client_id,
            Some("owner-token"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn create_test_registration(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    client: &RegisteredClient,
    registration_access_token: &str,
) -> TestResult {
    preflight_dynamic_registration_schema(pool).await?;
    create_dynamic_registration(
        pool,
        &env.issuer_host,
        client,
        &["code".to_string()],
        registration_access_token,
        "test-dcr-configuration-create",
    )
    .await?;
    Ok(())
}

fn registration_request(
    method: Method,
    client_id: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<Request<Body>, axum::http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("/register/{client_id}"))
        .header("x-request-id", "test-dcr-configuration-http");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    builder.body(Body::from(body.map_or_else(String::new, Value::to_string)))
}

async fn response_json(response: Response) -> TestResult<Value> {
    let bytes = body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn test_router(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult<axum::Router> {
    Ok(crate::web::router::build_router(
        test_app_state(pool.clone(), env).await?,
    ))
}

async fn test_app_state(pool: PgPool, env: &TestDcrEnvironment) -> TestResult<AppState> {
    let cfg = Arc::new(crate::config::ServerConfig {
        transport: crate::config::TransportSecurityConfig::default(),
        ..crate::config::ServerConfig::default()
    });
    let key_manager: Arc<dyn crate::kms::KeyManager> =
        Arc::new(crate::kms::InMemoryKeyManager::new());
    let token_issuer =
        crate::authcode::TokenIssuer::new_process_local_for_tests(Arc::clone(&key_manager));
    let token_store = token_issuer.token_store.clone();
    let token_validator =
        crate::authcode::TokenValidator::new(token_store.clone(), Arc::clone(&key_manager));
    let par_endpoint = Arc::new(test_par_endpoint()?);
    let par_store = par_endpoint.store();
    let clients = Arc::new(ClientRegistry::new_process_local_for_tests());
    let revision =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            &pool,
            &env.issuer_host,
        )
        .await?;
    let runtime_authority = crate::web::RuntimeAuthorityState::from_database_revision(
        Arc::new(env.issuer_host.clone()),
        revision,
    );
    runtime_authority
        .try_synchronize_client_projection_from_database(&pool, clients.as_ref())
        .await?;

    Ok(AppState {
        cfg: Arc::clone(&cfg),
        base_url: Arc::new(env.issuer_url.clone()),
        issuer: Arc::new(env.issuer_url.clone()),
        environment_id: env.environment_id,
        runtime_authority,
        runtime_restart: crate::runtime_restart::RuntimeRestartState::new(),
        readiness: crate::web::ReadinessState::new(),
        clients,
        tokens: crate::web::TokenState {
            issuer: Arc::new(token_issuer),
            validator: Arc::new(token_validator),
            store: Arc::new(token_store),
        },
        transport: crate::middleware::TransportSecurity::new(cfg.transport.clone()),
        dpop: Arc::new(crate::middleware::DpopMiddleware::new_process_local_for_tests()),
        protocol: crate::web::ProtocolState {
            par_endpoint,
            par_store,
            request_object_jti_store: Arc::new(
                crate::request_object_store::RequestObjectJtiStore::new_process_local_for_tests(
                    Duration::from_secs(60),
                ),
            ),
            stepup_store: Arc::new(
                crate::stepup::StepUpStore::new_process_local_with_ttl_for_tests(
                    Duration::from_secs(60),
                ),
            ),
        },
        oidc: crate::web::OidcState {
            config: None,
            sessions: None,
            userinfo_endpoint: None,
        },
        db_pool: pool,
        registry: Arc::new(prometheus::Registry::new()),
        browser_auth: crate::web::BrowserAuthState {
            auth_sessions: Arc::new(
                crate::web::AuthSessionStore::new_process_local_with_limits_for_tests(3600, 10),
            ),
        },
        upstream: crate::web::UpstreamState {
            logout_relay_store: Arc::new(
                crate::web::UpstreamLogoutRelayStore::new_process_local_with_ttl_secs_for_tests(60),
            ),
            auth_store: Arc::new(crate::upstream::UpstreamAuthStore::new_process_local_for_tests()),
            discovery_cache: Arc::new(crate::upstream::NonAuthoritativeMetadataCache::<
                crate::oidc::OidcDiscovery,
            >::with_ttl_secs(60)),
            jwks_cache: Arc::new(crate::upstream::NonAuthoritativeMetadataCache::<
                aegaeon_jose::jwk::JwkSet,
            >::with_ttl_secs(60)),
        },
        dcr_enabled: true,
        dcr_require_client_jwt_kid: false,
        dcr_allowed_algs: Arc::new(HashSet::new()),
        dcr_validation_config: crate::dcr::DcrValidationConfig::default(),
        dcr_required_bearer_hash: None,
        dcr_scope_allowlist: Arc::new(vec!["openid".to_string()]),
        management: crate::web::management::ManagementState::new_process_local_for_tests(),
        federation: crate::web::FederationState {
            trust_anchors: Arc::new(crate::federation::InMemoryTrustAnchorRepo::new()),
            entity_cache: Arc::new(crate::federation::InMemoryEntityCacheRepo::new()),
            chain_cache: Arc::new(crate::federation::InMemoryTrustChainCacheRepo::new()),
            cache_config: crate::federation::FederationCacheConfig::default(),
        },
        keys: crate::web::KeyManagersState {
            access_token: key_manager,
            jwt_introspection: None,
        },
        device: crate::web::DeviceState {
            code_store: Arc::new(
                crate::device_authz::DeviceCodeStore::new_process_local_for_tests(),
            ),
            csrf_store: Arc::new(
                crate::device_authz::CsrfTokenStore::new_process_local_for_tests(),
            ),
            local_auth_csrf_store: Arc::new(
                crate::device_authz::CsrfTokenStore::new_process_local_for_tests(),
            ),
            local_login_rate_limiter: Arc::new(
                crate::device_authz::VerificationRateLimiter::new_process_local_for_tests(),
            ),
            rate_limiter: Arc::new(
                crate::device_authz::VerificationRateLimiter::new_process_local_for_tests(),
            ),
        },
    })
}

fn test_par_endpoint() -> TestResult<crate::par::ParEndpoint> {
    let registry = Arc::new(prometheus::Registry::new());
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&registry)?;
    let integration = Arc::new(crate::metrics_integration::MetricsIntegration::new(
        Arc::new(metrics),
    ));
    Ok(crate::par::ParEndpoint::new(
        integration,
        Arc::new(crate::par::ParStore::new_process_local_for_tests()),
    ))
}

async fn test_pg_pool() -> TestResult<Option<PgPool>> {
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
    Ok(Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await?,
    ))
}

async fn setup_test_dcr_environment(pool: &PgPool) -> Result<TestDcrEnvironment, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let team_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let environment_id = Uuid::new_v4();
    let configuration_version_id = Uuid::new_v4();
    let suffix = &environment_id.to_string()[..8];
    let team_slug = format!("dcrhttpteam{suffix}");
    let tenant_slug = format!("dcrhttptenant{suffix}");
    let environment_slug = format!("dcrhttpenv{suffix}");
    let issuer_host = format!("{environment_slug}.test.example.com");
    let issuer_url = format!("https://{issuer_host}");
    let configuration_document = json!({
        "schemaVersion": 1,
        "issuerHost": issuer_host,
        "issuerUrl": issuer_url,
        "policy": PolicyDocument::default(),
        "scopeAllowlist": ["openid"],
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
        "INSERT INTO aegaeon.tenants (id, team_id, slug, name, region) \
         VALUES ($1, $2, $3, $4, 'test')",
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(&tenant_slug)
    .bind(&tenant_slug)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO aegaeon.environments (id, tenant_id, name, slug, issuer_host) \
         VALUES ($1, $2, $3, $4, $5)",
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
  id, environment_id, version_number, configuration_hash, status, configuration_document
) VALUES ($1, $2, 1, $3, 'ACTIVE', $4)
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .bind(format!("test-{suffix}"))
    .bind(configuration_document)
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
INSERT INTO aegaeon.oauth_profiles (
  environment_id, configuration_version_id, name, profile_type, is_default,
  require_pkce, require_state_parameter, require_iss_parameter, sender_constrained,
  enforce_refresh_sender_binding, allowed_grant_types, token_endpoint_auth_methods_allowed
) VALUES (
  $1, $2, 'dcr-http-default', 'DOWNSTREAM', true,
  true, true, true, 'NONE', true, $3, $4
)
        ",
    )
    .bind(environment_id)
    .bind(configuration_version_id)
    .bind(vec!["authorization_code".to_string()])
    .bind(vec!["none".to_string()])
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(TestDcrEnvironment {
        team_id,
        tenant_id,
        environment_id,
        issuer_host,
        issuer_url,
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
        "DELETE FROM aegaeon.oauth_profiles WHERE environment_id = $1",
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

fn finish_test(result: TestResult, cleanup: Result<(), sqlx::Error>) -> TestResult {
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error.into()),
        (Err(test_error), Ok(())) => Err(test_error),
        (Err(test_error), Err(cleanup_error)) => {
            Err(io::Error::other(format!("{test_error}; cleanup failed: {cleanup_error}")).into())
        }
    }
}

fn sample_registered_client(client_id: &str) -> RegisteredClient {
    RegisteredClient {
        client_id: client_id.to_string(),
        client_secret: None,
        redirect_uris: vec!["https://client.example.com/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        token_endpoint_auth_method: "none".to_string(),
        jwks_pem: None,
        inline_jwks: None,
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        allowed_scopes: vec!["openid".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        registration_access_token: None,
        client_id_issued_at: Some(1_700_000_000),
    }
}
