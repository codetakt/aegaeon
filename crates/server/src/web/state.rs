use aegaeon_jose::jwk::JwkSet;
use prometheus::Registry;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::authcode::{store::TokenStore, TokenIssuer, TokenValidator};
use crate::client_registry::ClientRegistry;
use crate::config::ServerConfig;
use crate::dcr::DcrValidationConfig;
use crate::device_authz::{CsrfTokenStore, DeviceCodeStore, VerificationRateLimiter};
use crate::federation::{
    EntityCacheRepository, FederationCacheConfig, TrustAnchorRepository, TrustChainCacheRepository,
};
use crate::kms::KeyManager;
use crate::middleware::tls::TransportSecurity;
use crate::middleware::DpopMiddleware;
use crate::oidc::{OidcConfig, OidcDiscovery, OidcSessionStore, UserinfoEndpoint};
use crate::par::{ParEndpoint, ParStore};
use crate::request_object_store::RequestObjectJtiStore;
use crate::runtime_authority::RuntimeAuthorityState;
use crate::runtime_configuration::RuntimeAuthorityRevision;
use crate::runtime_restart::RuntimeRestartState;
use crate::stepup::StepUpStore;
use crate::upstream::{NonAuthoritativeMetadataCache, UpstreamAuthStore};

use super::auth_session::AuthSessionStore;
use super::management;
use super::upstream_logout_relay::UpstreamLogoutRelayStore;

pub(super) const RUNTIME_AUTHORITY_DATABASE_REVISION_CACHE_TTL: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<ServerConfig>,
    pub base_url: Arc<String>,
    pub issuer: Arc<String>,
    pub environment_id: Uuid,
    pub runtime_authority: RuntimeAuthorityState,
    pub runtime_restart: RuntimeRestartState,
    pub readiness: ReadinessState,
    pub clients: Arc<ClientRegistry>,
    pub tokens: TokenState,
    pub transport: TransportSecurity,
    pub dpop: Arc<DpopMiddleware>,
    pub protocol: ProtocolState,
    pub oidc: OidcState,
    pub db_pool: PgPool,
    pub registry: Arc<Registry>,
    pub browser_auth: BrowserAuthState,
    pub upstream: UpstreamState,
    pub dcr_enabled: bool,
    pub dcr_require_client_jwt_kid: bool,
    pub dcr_allowed_algs: Arc<HashSet<String>>,
    pub dcr_validation_config: DcrValidationConfig,
    pub dcr_required_bearer_hash: Option<String>,
    pub dcr_scope_allowlist: Arc<Vec<String>>,
    pub management: management::ManagementState,
    pub federation: FederationState,
    pub keys: KeyManagersState,
    pub device: DeviceState,
}

#[derive(Clone)]
pub struct TokenState {
    pub issuer: Arc<TokenIssuer>,
    pub validator: Arc<TokenValidator>,
    pub store: Arc<TokenStore>,
}

#[derive(Clone)]
pub struct ProtocolState {
    pub par_endpoint: Arc<ParEndpoint>,
    pub par_store: Arc<ParStore>,
    pub request_object_jti_store: Arc<RequestObjectJtiStore>,
    pub stepup_store: Arc<StepUpStore>,
}

#[derive(Clone)]
pub struct OidcState {
    pub config: Option<Arc<OidcConfig>>,
    pub sessions: Option<OidcSessionStore>,
    pub userinfo_endpoint: Option<Arc<UserinfoEndpoint>>,
}

#[derive(Clone)]
pub struct BrowserAuthState {
    pub auth_sessions: Arc<AuthSessionStore>,
}

#[derive(Clone)]
pub struct UpstreamState {
    pub logout_relay_store: Arc<UpstreamLogoutRelayStore>,
    pub auth_store: Arc<UpstreamAuthStore>,
    pub discovery_cache: Arc<NonAuthoritativeMetadataCache<OidcDiscovery>>,
    pub jwks_cache: Arc<NonAuthoritativeMetadataCache<JwkSet>>,
}

#[derive(Clone)]
pub struct FederationState {
    /// Federation trust anchor repository (PostgreSQL-backed in production).
    pub trust_anchors: Arc<dyn TrustAnchorRepository>,
    /// Federation entity cache repository.
    pub entity_cache: Arc<dyn EntityCacheRepository>,
    /// Federation trust chain cache repository.
    pub chain_cache: Arc<dyn TrustChainCacheRepository>,
    /// Federation cache configuration (TTLs).
    pub cache_config: FederationCacheConfig,
}

#[derive(Clone)]
pub struct KeyManagersState {
    /// Key manager for access-token JWTs.
    pub access_token: Arc<dyn KeyManager>,
    /// Optional dedicated key manager for JWT introspection responses.
    pub jwt_introspection: Option<Arc<dyn KeyManager>>,
}

#[derive(Clone)]
pub struct DeviceState {
    /// RFC 8628 Device Authorization Grant: device code store.
    pub code_store: Arc<DeviceCodeStore>,
    /// CSRF token store for device verification UI.
    pub csrf_store: Arc<CsrfTokenStore>,
    /// CSRF token store for server-rendered local authentication forms.
    pub local_auth_csrf_store: Arc<CsrfTokenStore>,
    /// Rate limiter for local password login attempts.
    pub local_login_rate_limiter: Arc<VerificationRateLimiter>,
    /// Rate limiter for device verification endpoint.
    pub rate_limiter: Arc<VerificationRateLimiter>,
}

#[derive(Clone)]
pub struct ReadinessState {
    revision: Arc<RwLock<Option<CachedReadinessRevision>>>,
}

#[derive(Clone)]
struct CachedReadinessRevision {
    revision: RuntimeAuthorityRevision,
    expires_at: Instant,
}

impl ReadinessState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            revision: Arc::new(RwLock::new(None)),
        }
    }

    pub(super) fn current_revision(&self) -> Option<RuntimeAuthorityRevision> {
        let cached = self.revision.read().ok()?.clone()?;
        (Instant::now() < cached.expires_at).then_some(cached.revision)
    }

    pub(super) fn store_revision(&self, revision: RuntimeAuthorityRevision, ttl: Duration) {
        if let Ok(mut cached) = self.revision.write() {
            *cached = Some(CachedReadinessRevision {
                revision,
                expires_at: Instant::now() + ttl,
            });
        }
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub(super) struct RuntimeAuthorityServices {
    pub(super) runtime_authority: RuntimeAuthorityState,
    pub(super) runtime_restart: RuntimeRestartState,
    pub(super) readiness: ReadinessState,
    pub(super) clients: Arc<ClientRegistry>,
    pub(super) db_pool: PgPool,
}

impl AppState {
    #[must_use]
    pub(super) fn runtime_authority_services(&self) -> RuntimeAuthorityServices {
        RuntimeAuthorityServices {
            runtime_authority: self.runtime_authority.clone(),
            runtime_restart: self.runtime_restart.clone(),
            readiness: self.readiness.clone(),
            clients: Arc::clone(&self.clients),
            db_pool: self.db_pool.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_state_source_body() -> &'static str {
        include_str!("state.rs")
            .split_once("pub struct AppState {")
            .expect("AppState source should contain struct declaration")
            .1
            .split_once("\n}")
            .expect("AppState source should contain struct terminator")
            .0
    }

    fn revision(fingerprint: &str) -> RuntimeAuthorityRevision {
        RuntimeAuthorityRevision::new_unchecked_for_tests(
            uuid::Uuid::nil(),
            "configuration".to_string(),
            "keys".to_string(),
            fingerprint.to_string(),
            "dcr".to_string(),
        )
    }

    #[test]
    fn app_state_keeps_runtime_capabilities_grouped() {
        let app_state = app_state_source_body();
        for required in [
            "pub tokens: TokenState",
            "pub protocol: ProtocolState",
            "pub oidc: OidcState",
            "pub browser_auth: BrowserAuthState",
            "pub upstream: UpstreamState",
            "pub federation: FederationState",
            "pub keys: KeyManagersState",
            "pub device: DeviceState",
        ] {
            assert!(
                app_state.contains(required),
                "AppState must retain grouped runtime capability field `{required}`"
            );
        }

        for forbidden in [
            "pub token_issuer:",
            "pub token_validator:",
            "pub token_store:",
            "pub par_endpoint:",
            "pub par_store:",
            "pub request_object_jti_store:",
            "pub stepup_store:",
            "pub oidc_config:",
            "pub oidc_sessions:",
            "pub userinfo_endpoint:",
            "pub auth_sessions:",
            "pub upstream_logout_relay_store:",
            "pub upstream_auth_store:",
            "pub upstream_discovery_cache:",
            "pub upstream_jwks_cache:",
            "pub federation_trust_anchors:",
            "pub federation_entity_cache:",
            "pub federation_chain_cache:",
            "pub federation_cache_config:",
            "pub key_manager:",
            "pub jwt_introspection_key_manager:",
            "pub federation_key_manager:",
            "pub device_code_store:",
            "pub device_csrf_store:",
            "pub local_auth_csrf_store:",
            "pub local_login_rate_limiter:",
            "pub device_rate_limiter:",
        ] {
            assert!(
                !app_state.contains(forbidden),
                "AppState must not regress to flat runtime field `{forbidden}`"
            );
        }
    }

    #[test]
    fn readiness_state_returns_unexpired_revision() {
        let readiness = ReadinessState::new();
        readiness.store_revision(revision("clients-a"), Duration::from_secs(1));

        let cached = readiness
            .current_revision()
            .expect("readiness revision should be cached");
        assert_eq!(cached.active_runtime_client_fingerprint(), "clients-a");
    }

    #[test]
    fn readiness_state_does_not_return_expired_revision() {
        let readiness = ReadinessState::new();
        readiness.store_revision(revision("clients-a"), Duration::ZERO);

        assert!(readiness.current_revision().is_none());
    }
}
