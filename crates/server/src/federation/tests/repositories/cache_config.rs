// ── Federation Cache Config ─────────────────────────────────────

#[test]
fn federation_cache_config_default() {
    let config = FederationCacheConfig::default();
    assert_eq!(config.entity_cache_ttl, Duration::from_secs(30 * 60));
    assert_eq!(config.trust_chain_cache_ttl, Duration::from_secs(60 * 60));
    assert_eq!(config.cache_max_entries, DEFAULT_FEDERATION_CACHE_MAX_ENTRIES);
}

#[test]
fn federation_cache_ttl_bounds_are_finite() {
    assert!(!valid_federation_cache_ttl_secs(0));
    assert!(valid_federation_cache_ttl_secs(
        MAX_FEDERATION_CACHE_TTL_SECS
    ));
    assert!(!valid_federation_cache_ttl_secs(
        MAX_FEDERATION_CACHE_TTL_SECS + 1
    ));
}
