use super::*;
use super::test_prelude::*;
use crate::test_utils::env_inventory::{
    assert_env_inventory_complete_for_sources, keys_with_authority, EnvAuthority,
};
use axum::body::{self, Body};
use axum::http::{Method, Request, StatusCode};
use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::io;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn StdError>>;
const TEST_RSA_PRIVATE_KEY_PEM: &str =
    include_str!("../../../../../tests/fixtures/rsa2048-private.pk8.pem");
const MANAGEMENT_ENV_INVENTORY: &[(&str, EnvAuthority)] = &[
    (
        "AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN",
        EnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_MANAGEMENT_COOKIE_SECURE",
        EnvAuthority::RemovedSystemBootstrap,
    ),
    (
        "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
        EnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
        EnvAuthority::SharedRuntimeStore,
    ),
];

struct EnvVarGuard {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: impl Into<OsString>) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value.into());
        Self { key, previous }
    }

    fn unset(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

fn test_management_config() -> ManagementConfig {
    ManagementConfig {
        allowed_origins: vec!["https://admin.example.com".to_string()],
        issuer_base_domain: "example.com".to_string(),
        cookie_secure: false,
        session_ttl_secs: 60,
        max_sessions: DEFAULT_MAX_SESSIONS,
        bootstrap_token_sha256: None,
    }
}

fn test_par_endpoint() -> Result<crate::par::ParEndpoint, Box<dyn StdError>> {
    let registry = Arc::new(prometheus::Registry::new());
    let metrics = aegaeon_observability::metrics::OAuthMetrics::new(&registry)?;
    let integration = Arc::new(MetricsIntegration::new(Arc::new(metrics)));
    Ok(crate::par::ParEndpoint::new(
        integration,
        Arc::new(crate::par::ParStore::new_process_local_for_tests()),
    ))
}

fn test_app_state(pool: PgPool, management: ManagementState) -> Result<AppState, Box<dyn StdError>>
{
    let cfg = ServerConfig {
        transport: crate::config::TransportSecurityConfig::default(),
        ..ServerConfig::default()
    };
    let cfg = Arc::new(cfg);
    let key_manager: Arc<dyn crate::kms::KeyManager> =
        Arc::new(crate::kms::InMemoryKeyManager::new());
    let token_issuer =
        crate::authcode::TokenIssuer::new_process_local_for_tests(Arc::clone(&key_manager));
    let token_store = token_issuer.token_store.clone();
    let token_validator =
        crate::authcode::TokenValidator::new(token_store.clone(), Arc::clone(&key_manager));
    let par_endpoint = Arc::new(test_par_endpoint()?);
    let par_store = par_endpoint.store();

    Ok(AppState {
        cfg: Arc::clone(&cfg),
        base_url: Arc::new("https://auth.example.com".to_string()),
        issuer: Arc::new("https://auth.example.com".to_string()),
        environment_id: uuid::Uuid::nil(),
        runtime_authority: crate::web::RuntimeAuthorityState::new_process_local_for_tests(
            "auth.example.com",
        ),
        runtime_restart: crate::runtime_restart::RuntimeRestartState::new(),
        readiness: crate::web::ReadinessState::new(),
        clients: Arc::new(crate::client_registry::ClientRegistry::new_process_local_for_tests()),
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
                    std::time::Duration::from_secs(60),
                ),
            ),
            stepup_store: Arc::new(
                crate::stepup::StepUpStore::new_process_local_with_ttl_for_tests(
                    std::time::Duration::from_secs(60),
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
                super::super::AuthSessionStore::new_process_local_with_limits_for_tests(3600, 10),
            ),
        },
        upstream: crate::web::UpstreamState {
            logout_relay_store: Arc::new(
                super::super::UpstreamLogoutRelayStore::new_process_local_with_ttl_secs_for_tests(
                    60,
                ),
            ),
            auth_store: Arc::new(crate::upstream::UpstreamAuthStore::new_process_local_for_tests()),
            discovery_cache: Arc::new(
                crate::upstream::NonAuthoritativeMetadataCache::<
                    crate::oidc::OidcDiscovery,
                >::with_ttl_secs(60),
            ),
            jwks_cache: Arc::new(
                crate::upstream::NonAuthoritativeMetadataCache::<aegaeon_jose::jwk::JwkSet>::with_ttl_secs(60),
            ),
        },
        dcr_enabled: false,
        dcr_require_client_jwt_kid: false,
        dcr_allowed_algs: Arc::new(HashSet::new()),
        dcr_validation_config: crate::dcr::DcrValidationConfig::default(),
        dcr_required_bearer_hash: None,
        dcr_scope_allowlist: Arc::new(Vec::new()),
        management,
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
                VerificationRateLimiter::new_process_local_for_tests(),
            ),
            rate_limiter: Arc::new(VerificationRateLimiter::new_process_local_for_tests()),
        },
    })
}

fn test_management_state() -> ManagementState {
    let cfg = test_management_config();
    let sessions = ManagementSessionStore::new_process_local_with_limits(
        cfg.session_ttl_secs,
        cfg.max_sessions,
    );
    ManagementState {
        cfg: Arc::new(cfg),
        sessions: Arc::new(sessions),
        login_rate_limiter: Arc::new(VerificationRateLimiter::new_process_local_for_tests()),
    }
}

async fn management_error_response_body(
    response: axum::response::Response,
) -> Result<crate::management::types::ErrorResponse, Box<dyn StdError>> {
    let bytes = body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Build a minimal router with only the security middleware and a
/// simple 200 OK handler behind it. No AppState/DB needed.
fn test_middleware_router(mgmt: ManagementState) -> Router {
    Router::new()
        .route("/test", get(|| async { StatusCode::OK.into_response() }))
        .route("/test", post(|| async { StatusCode::OK.into_response() }))
        .route(
            "/test",
            axum::routing::delete(|| async { StatusCode::OK.into_response() }),
        )
        .layer(middleware::from_fn_with_state(
            mgmt,
            management_security_middleware,
        ))
}

fn test_json_middleware_router(mgmt: ManagementState) -> Router {
    Router::new()
        .route(
            "/json",
            post(|Json(value): Json<serde_json::Value>| async move { Json(value).into_response() }),
        )
        .layer(middleware::from_fn_with_state(
            mgmt,
            management_security_middleware,
        ))
}

fn assert_no_store_and_request_id(resp: &Response) {
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        resp.headers().get(header::PRAGMA),
        Some(&HeaderValue::from_static("no-cache"))
    );
    assert!(resp.headers().contains_key("x-request-id"));
}
