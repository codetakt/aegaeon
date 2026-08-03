// ── CachedFederationFetcher ─────────────────────────────────────

#[test]
fn cached_fetcher_returns_cached_entity_config() {
    let _guard = raw_json_env_guard();
    let now = current_epoch_secs();
    let env_id = Uuid::new_v4();
    let config = FederationCacheConfig {
        entity_cache_ttl: Duration::from_secs(1800),
        trust_chain_cache_ttl: Duration::from_secs(3600),
        cache_max_entries: DEFAULT_FEDERATION_CACHE_MAX_ENTRIES,
        outbound_allowed_domains: Vec::new(),
    };

    let cache = InMemoryEntityCacheRepo::new();
    let key_manager = InMemoryKeyManager::new();
    let mut stmt = sample_entity_config("https://rp.example.com", now);
    stmt.jwks = Some(federation_jwks_value(&key_manager));
    let entity_configuration_jws = sign_entity_statement_for_test(&key_manager, &stmt);
    let parsed = must_ok(serde_json::to_value(&stmt));
    must_ok(cache.upsert(
        env_id,
        "https://rp.example.com",
        &entity_configuration_jws,
        &parsed,
        stmt.exp
    ));

    // Inner fetcher should NOT be called (entity not added)
    let inner = MockFetcher::new();
    let fetcher = CachedFederationFetcher::new(inner, Box::new(cache), env_id, &config);

    let result = block_on_test_future(
        fetcher.fetch_entity_configuration("https://rp.example.com"),
    );
    assert!(result.is_ok());
    assert_eq!(must_ok(result).iss, "https://rp.example.com");
}

#[test]
fn cached_fetcher_does_not_trust_parsed_statement_without_valid_jws() {
    let _guard = raw_json_env_guard();
    let now = current_epoch_secs();
    let env_id = Uuid::new_v4();
    let config = FederationCacheConfig::default();

    let cache = InMemoryEntityCacheRepo::new();
    let stmt = sample_entity_config("https://rp.example.com", now);
    let parsed = must_ok(serde_json::to_value(&stmt));
    must_ok(cache.upsert(
        env_id,
        "https://rp.example.com",
        "not-a-compact-jws",
        &parsed,
        stmt.exp
    ));

    let inner = MockFetcher::new();
    let fetcher = CachedFederationFetcher::new(inner, Box::new(cache), env_id, &config);

    let result = block_on_test_future(
        fetcher.fetch_entity_configuration("https://rp.example.com"),
    );
    assert!(
        result.is_err(),
        "parsed cached JSON must not be trusted when the compact JWS is invalid"
    );
}

#[tokio::test]
async fn cached_fetcher_delegates_on_miss() {
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let config = FederationCacheConfig {
        entity_cache_ttl: Duration::from_secs(1800),
        trust_chain_cache_ttl: Duration::from_secs(3600),
        cache_max_entries: DEFAULT_FEDERATION_CACHE_MAX_ENTRIES,
        outbound_allowed_domains: Vec::new(),
    };

    let cache = InMemoryEntityCacheRepo::new();
    let mut inner = MockFetcher::new();
    inner.add_entity_config(
        "https://rp.example.com",
        sample_entity_config("https://rp.example.com", now),
    );

    let fetcher = CachedFederationFetcher::new(inner, Box::new(cache), env_id, &config);
    let result = fetcher
        .fetch_entity_configuration("https://rp.example.com")
        .await;
    assert!(result.is_ok());
    assert_eq!(must_ok(result).iss, "https://rp.example.com");
}

#[test]
fn cached_fetcher_delegates_subordinate_statements() {
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let config = FederationCacheConfig::default();

    let cache = InMemoryEntityCacheRepo::new();
    let mut inner = MockFetcher::new();
    inner.add_subordinate_stmt(
        "https://ta.example.com",
        "https://rp.example.com",
        sample_subordinate_statement("https://ta.example.com", "https://rp.example.com", now),
    );

    let fetcher = CachedFederationFetcher::new(inner, Box::new(cache), env_id, &config);
    let jwks = sample_jwks();
    let authority_config = sample_entity_config("https://ta.example.com", now);
    let result = block_on_test_future(fetcher.fetch_subordinate_statement(
        "https://ta.example.com",
        &authority_config,
        "https://rp.example.com",
        &jwks,
    ));
    assert!(result.is_ok());
}
