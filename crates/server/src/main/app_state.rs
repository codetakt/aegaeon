use std::sync::Arc;

use aegaeon_server::client_registry::ClientRegistry;
use aegaeon_server::config::ServerConfig;
use aegaeon_server::kms::KeyManager;
use aegaeon_server::middleware::tls::TransportSecurity;
use aegaeon_server::middleware::DpopMiddleware;
use aegaeon_server::oidc::{OidcConfig, OidcSessionStore, UserinfoEndpoint};
use aegaeon_server::runtime_authority::RuntimeAuthorityState;
use aegaeon_server::runtime_restart::RuntimeRestartState;
use aegaeon_server::web::management::ManagementState;
use aegaeon_server::web::{
    AppState, BrowserAuthState, DeviceState, FederationState, KeyManagersState, OidcState,
    ProtocolState, ReadinessState, TokenState, UpstreamState,
};
use prometheus::Registry;
use sqlx::PgPool;
use uuid::Uuid;

use super::browser_auth_runtime::BrowserAuthRuntime;
use super::dcr_runtime::DcrRuntime;
use super::device_runtime::DeviceRuntimeStores;
use super::federation_runtime::FederationRuntime;
use super::protocol_runtime::ProtocolRuntimeStores;
use super::sync_runtime::RuntimeSyncPlan;
use super::token_runtime::TokenRuntime;
use super::upstream_runtime::UpstreamRuntime;

pub(super) struct AppStateParts {
    pub(super) cfg: Arc<ServerConfig>,
    pub(super) base_url: String,
    pub(super) issuer: String,
    pub(super) environment_id: Uuid,
    pub(super) runtime_authority: RuntimeAuthorityState,
    pub(super) runtime_restart: RuntimeRestartState,
    pub(super) clients: Arc<ClientRegistry>,
    pub(super) token: TokenRuntime,
    pub(super) transport: TransportSecurity,
    pub(super) dpop: Arc<DpopMiddleware>,
    pub(super) protocol: ProtocolRuntimeStores,
    pub(super) oidc: Option<Arc<OidcConfig>>,
    pub(super) oidc_sessions: Option<OidcSessionStore>,
    pub(super) userinfo_endpoint: Option<Arc<UserinfoEndpoint>>,
    pub(super) db_pool: PgPool,
    pub(super) registry: Arc<Registry>,
    pub(super) upstream: UpstreamRuntime,
    pub(super) browser_auth: BrowserAuthRuntime,
    pub(super) dcr: DcrRuntime,
    pub(super) runtime_sync: RuntimeSyncPlan,
    pub(super) management: ManagementState,
    pub(super) federation: FederationRuntime,
    pub(super) key_manager: Arc<dyn KeyManager>,
    pub(super) jwt_introspection_key_manager: Option<Arc<dyn KeyManager>>,
    pub(super) device: DeviceRuntimeStores,
}

pub(super) fn app_state_from_parts(parts: AppStateParts) -> AppState {
    let AppStateParts {
        cfg,
        base_url,
        issuer,
        environment_id,
        runtime_authority,
        runtime_restart,
        clients,
        token,
        transport,
        dpop,
        protocol,
        oidc,
        oidc_sessions,
        userinfo_endpoint,
        db_pool,
        registry,
        upstream,
        browser_auth,
        dcr,
        runtime_sync: _runtime_sync,
        management,
        federation,
        key_manager,
        jwt_introspection_key_manager,
        device,
    } = parts;

    AppState {
        cfg,
        base_url: Arc::new(base_url),
        issuer: Arc::new(issuer),
        environment_id,
        runtime_authority,
        runtime_restart,
        readiness: ReadinessState::new(),
        clients,
        tokens: TokenState {
            issuer: token.issuer,
            validator: token.validator,
            store: token.store,
        },
        transport,
        dpop,
        protocol: ProtocolState {
            par_endpoint: protocol.par_endpoint,
            par_store: protocol.par_store,
            request_object_jti_store: protocol.request_object_jti_store,
            stepup_store: protocol.stepup_store,
        },
        oidc: OidcState {
            config: oidc,
            sessions: oidc_sessions,
            userinfo_endpoint,
        },
        db_pool,
        registry,
        browser_auth: BrowserAuthState {
            auth_sessions: browser_auth.auth_sessions,
        },
        upstream: UpstreamState {
            logout_relay_store: upstream.logout_relay_store,
            auth_store: upstream.auth_store,
            discovery_cache: upstream.discovery_cache,
            jwks_cache: upstream.jwks_cache,
        },
        dcr_enabled: dcr.enabled,
        dcr_require_client_jwt_kid: dcr.require_client_jwt_kid,
        dcr_allowed_algs: Arc::new(dcr.allowed_algs),
        dcr_validation_config: dcr.validation_config,
        dcr_required_bearer_hash: dcr.required_bearer_hash,
        dcr_scope_allowlist: Arc::new(dcr.scope_allowlist),
        management,
        federation: FederationState {
            trust_anchors: federation.trust_anchors,
            entity_cache: federation.entity_cache,
            chain_cache: federation.chain_cache,
            cache_config: federation.cache_config,
        },
        keys: KeyManagersState {
            access_token: key_manager,
            jwt_introspection: jwt_introspection_key_manager,
        },
        device: DeviceState {
            code_store: device.device_code_store,
            csrf_store: device.device_csrf_store,
            local_auth_csrf_store: device.local_auth_csrf_store,
            local_login_rate_limiter: device.local_login_rate_limiter,
            rate_limiter: device.device_rate_limiter,
        },
    }
}
