use std::sync::Arc;

use crate::config::{RuntimeStateNamespace, ServerConfig};
use crate::management::types::PolicyDocument;
use crate::oidc::OidcDiscovery;
use crate::upstream::{NonAuthoritativeMetadataCache, UpstreamAuthStore};
use crate::web::CachedUpstreamJwks;
use crate::web::UpstreamLogoutRelayStore;
use anyhow::Result;

type UpstreamCachePair = (
    Arc<NonAuthoritativeMetadataCache<OidcDiscovery>>,
    Arc<NonAuthoritativeMetadataCache<CachedUpstreamJwks>>,
);

pub(super) struct UpstreamRuntime {
    pub(super) auth_store: Arc<UpstreamAuthStore>,
    pub(super) logout_relay_store: Arc<UpstreamLogoutRelayStore>,
    pub(super) discovery_cache: Arc<NonAuthoritativeMetadataCache<OidcDiscovery>>,
    pub(super) jwks_cache: Arc<NonAuthoritativeMetadataCache<CachedUpstreamJwks>>,
}

pub(super) fn upstream_runtime_for_authority(
    pool: &sqlx::PgPool,
    cfg: &ServerConfig,
    policy: &PolicyDocument,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<UpstreamRuntime> {
    let upstream = cfg.upstream();
    let auth_store = Arc::new(UpstreamAuthStore::from_postgres(
        pool.clone(),
        runtime_state_namespace,
        upstream.auth_ttl_secs(),
    )?);
    let logout_relay_store = Arc::new(UpstreamLogoutRelayStore::from_postgres(
        pool.clone(),
        runtime_state_namespace,
        upstream.logout_relay_ttl_secs(),
    )?);
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
