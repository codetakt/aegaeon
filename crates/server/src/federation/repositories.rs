// ─── DB Backend (Phase 2) ────────────────────────────────────────────────
//
// Repository traits and PostgreSQL implementations for persisting federation
// state:
//
//   TrustAnchorRepository  — configured trust anchors per environment
//   EntityCacheRepository  — entity configuration JWS cache
//   TrustChainCacheRepository — resolved trust chain cache
//
// Cache TTL is configurable via `FederationCacheConfig`. The default is
// 30 minutes for entity configurations and 60 minutes for trust chains.
//
// OIDC RP flow integration (wired in Phase 5, hardened in Phase 7–8):
//
//   1. On upstream `/authorize`, the trust chain is resolved via
//      TrustChainCacheRepository → CachedFederationFetcher → HTTP.
//      See `upstream_authorize()` in web/mod.rs.
//
//   2. Resolved metadata policy is applied to validate the upstream's
//      redirect_uris, grant_types, etc. via `TrustChain::resolved_metadata()`.
//
//   3. On `/callback`, the cached chain is reused to verify the ID token
//      issuer matches the leaf entity JWKS. Trust chain is re-verified
//      on callback (T-RP-2 fix, Phase 5).
//
//   4. Account linking uses the account_links table with environment-scoped
//      lookups and privacy-preserving upstream sub hashing (SHA-256 + base64url).
//
//   5. Upstream refresh rotation (OIDC-1-009, Phase 7): verified with
//      F* UpstreamRefresh.fst (17 lemmas) and e2e tests with mock IdP.
//
// Security considerations:
//   - SSRF (P8-SSRF-1/P8-SSRF-2): HttpFederationFetcher performs pre-flight
//     DNS resolution and rejects non-routable IPs (loopback, RFC 1918,
//     link-local, CGNAT, documentation, benchmarking, reserved). Redirect
//     targets are validated against private IP ranges and, when configured,
//     the domain allowlist. See crate::ssrf for the full implementation.
//   - Cache poisoning: Entity cache is per-environment (environment_id in the
//     unique index). JWS signature is verified before caching. Cache entries
//     expire via `expires_at` and are validated on read.
//   - Tenant isolation: All tables are scoped by environment_id with FK to
//     aegaeon.environments.

mod cache;
mod clock;
mod config;
#[cfg(test)]
mod memory;
mod postgres;
mod traits;
mod types;

#[cfg(test)]
pub(super) use cache::{reconstruct_chain_from_cache, trust_chain_cache_expires_at};
pub use cache::{
    resolve_trust_chain_cached, resolve_trust_chain_cached_with,
    resolve_trust_chain_jwts_cached_with, spawn_cache_cleanup, CachedFederationFetcher,
};
#[cfg(test)]
pub(super) use clock::current_unix_epoch_secs;
pub use config::{
    valid_federation_cache_max_entries, valid_federation_cache_ttl_secs, FederationCacheConfig,
    DEFAULT_FEDERATION_CACHE_MAX_ENTRIES, DEFAULT_FEDERATION_ENTITY_CACHE_TTL_SECS,
    DEFAULT_FEDERATION_TRUST_CHAIN_CACHE_TTL_SECS, MAX_FEDERATION_CACHE_MAX_ENTRIES,
    MAX_FEDERATION_CACHE_TTL_SECS,
};
#[cfg(test)]
pub(crate) use memory::{
    InMemoryEntityCacheRepo, InMemoryTrustAnchorRepo, InMemoryTrustChainCacheRepo,
};
#[cfg(test)]
pub(super) use postgres::storage_err;
pub use postgres::{PgEntityCacheRepository, PgTrustAnchorRepository, PgTrustChainCacheRepository};
pub use traits::{EntityCacheRepository, TrustAnchorRepository, TrustChainCacheRepository};
pub use types::{StoredEntityCache, StoredTrustAnchor, StoredTrustChain};
