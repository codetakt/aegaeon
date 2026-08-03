use std::sync::Arc;

use aegaeon_jose::jwk::JwkSet;
use aegaeon_server::config::{RuntimeStateNamespace, ServerConfig};
use aegaeon_server::management::types::PolicyDocument;
use aegaeon_server::oidc::OidcDiscovery;
use aegaeon_server::upstream::{NonAuthoritativeMetadataCache, UpstreamAuthStore};
use aegaeon_server::web::UpstreamLogoutRelayStore;
use anyhow::Result;

type UpstreamCachePair = (
    Arc<NonAuthoritativeMetadataCache<OidcDiscovery>>,
    Arc<NonAuthoritativeMetadataCache<JwkSet>>,
);

pub(super) struct UpstreamRuntime {
    pub(super) auth_store: Arc<UpstreamAuthStore>,
    pub(super) logout_relay_store: Arc<UpstreamLogoutRelayStore>,
    pub(super) discovery_cache: Arc<NonAuthoritativeMetadataCache<OidcDiscovery>>,
    pub(super) jwks_cache: Arc<NonAuthoritativeMetadataCache<JwkSet>>,
}

pub(super) fn upstream_runtime_for_authority(
    cfg: &ServerConfig,
    policy: &PolicyDocument,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<UpstreamRuntime> {
    let upstream = cfg.upstream();
    let auth_store = Arc::new(
        UpstreamAuthStore::try_new_from_shared_store_env_with_ttl_secs(
            upstream.auth_ttl_secs(),
            runtime_state_namespace,
        )?,
    );
    let logout_relay_store = Arc::new(
        UpstreamLogoutRelayStore::try_new_from_shared_store_env_with_ttl_secs(
            upstream.logout_relay_ttl_secs(),
            runtime_state_namespace,
        )?,
    );
    let (discovery_cache, jwks_cache) = upstream_caches_for_authority(policy)?;

    Ok(UpstreamRuntime {
        auth_store,
        logout_relay_store,
        discovery_cache,
        jwks_cache,
    })
}

fn upstream_caches_for_authority(policy: &PolicyDocument) -> Result<UpstreamCachePair> {
    Ok((
        Arc::new(
            NonAuthoritativeMetadataCache::try_new_non_authoritative_with_ttl_secs_and_max_entries(
                "upstream_discovery_cache_ttl_seconds",
                u64::from(policy.upstream_discovery_cache_ttl_seconds),
                "upstream_discovery_cache_max_entries",
                policy.upstream_discovery_cache_max_entries,
            )?,
        ),
        Arc::new(
            NonAuthoritativeMetadataCache::try_new_non_authoritative_with_ttl_secs_and_max_entries(
                "upstream_jwks_cache_ttl_seconds",
                u64::from(policy.upstream_jwks_cache_ttl_seconds),
                "upstream_jwks_cache_max_entries",
                policy.upstream_jwks_cache_max_entries,
            )?,
        ),
    ))
}
