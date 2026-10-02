//! Shared database-backed HTTP test fixtures. No production request checks are bypassed.
mod authorization;
mod projections;
use super::AppState;
use crate::{
    client_registry::{ClientRegistry, RegisteredClient},
    management::types::PolicyDocument,
};
pub(crate) use authorization::{
    derive_test_authorization_runtime, reload_authorization_runtime, seed_oidc_configuration,
    update_test_policy,
};
pub(crate) use projections::seed_test_projection;
use serde_json::json;
use sqlx::PgPool;
use std::{collections::HashSet, error::Error, io, sync::Arc, time::Duration};
use uuid::Uuid;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

pub(crate) struct TestEnvironment {
    pub(crate) team_id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) environment_id: Uuid,
    pub(crate) issuer_host: String,
    pub(crate) issuer_url: String,
}

pub(crate) async fn test_app_state(pool: PgPool, env: &TestEnvironment) -> TestResult<AppState> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(pool.options().get_max_connections())
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let mut baseline = crate::config::ServerConfig {
        transport: crate::config::TransportSecurityConfig::default(),
        ..crate::config::ServerConfig::default()
    };
    // These local HTTP fixtures do not run behind a TLS-terminating proxy.
    baseline.security_policy.transport.enforce_trusted_proxy = false;
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
    let loaded =
        crate::runtime_configuration::load_database_runtime_configuration(&pool, &env.issuer_host)
            .await?;
    let derived = derive_test_authorization_runtime(loaded, baseline).await?;
    let cfg = derived.configuration();
    let oidc_config = derived.oidc();
    let runtime_authority = crate::web::RuntimeAuthorityState::from_authorization_runtime(derived);
    runtime_authority
        .try_synchronize_client_projection_from_database(&pool, clients.as_ref())
        .await?;

    let token_issuer = token_issuer
        .with_issuer(env.issuer_url.clone())
        .with_oidc(oidc_config.as_deref().cloned());
    let token_validator = token_validator.with_issuer(Some(env.issuer_url.clone()));
    let mut state = AppState {
        subject_namespace: None,
        application_authority: None,
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
            config: oidc_config,
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
    };
    state.validate_subject_namespace().await?;
    Ok(state)
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

pub(crate) async fn test_pg_pool() -> TestResult<Option<PgPool>> {
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

/// Setup-only supplier for owned integration databases. Never used to validate
/// a positive runtime permit or passed to a production handler.
pub(crate) async fn test_admin_pool(runtime: &PgPool) -> TestResult<PgPool> {
    let options: sqlx::postgres::PgConnectOptions =
        std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?.parse()?;
    let actual = runtime.connect_options();
    let database = actual
        .get_database()
        .ok_or("fixture database name missing")?;
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.database(database))
        .await?)
}

pub(crate) async fn setup_test_environment(pool: &PgPool) -> Result<TestEnvironment, sqlx::Error> {
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

    Ok(TestEnvironment {
        team_id,
        tenant_id,
        environment_id,
        issuer_host,
        issuer_url,
    })
}

/// Namespace ownership and private audit history survive every test operation.
/// The enclosing lane owns and tears down the entire disposable database.
pub(crate) async fn cleanup_test_environment(
    _pool: &PgPool,
    _env: &TestEnvironment,
) -> Result<(), sqlx::Error> {
    Ok(())
}

pub(crate) fn finish_test(result: TestResult, cleanup: Result<(), sqlx::Error>) -> TestResult {
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error.into()),
        (Err(test_error), Ok(())) => Err(test_error),
        (Err(test_error), Err(cleanup_error)) => {
            Err(io::Error::other(format!("{test_error}; cleanup failed: {cleanup_error}")).into())
        }
    }
}

pub(crate) fn sample_registered_client(client_id: &str) -> RegisteredClient {
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
