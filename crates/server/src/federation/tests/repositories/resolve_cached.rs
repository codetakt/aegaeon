// ── resolve_trust_chain_cached ──────────────────────────────────

fn requested_anchor_order_fixture(
    first_ta_id: &str,
    second_ta_id: &str,
    leaf_id: &str,
    now: i64,
) -> (MockFetcher, Vec<TrustAnchor>, SignedDirectChain, SignedDirectChain) {
    let first_chain = signed_direct_chain(first_ta_id, leaf_id, now);
    let second_chain = signed_direct_chain(second_ta_id, leaf_id, now);

    let mut leaf_config = first_chain.leaf_config.clone();
    leaf_config.authority_hints = Some(vec![second_ta_id.to_string(), first_ta_id.to_string()]);

    let mut fetcher = MockFetcher::new();
    fetcher.add_entity_config_with_jws(leaf_id, leaf_config, first_chain.leaf_jws.clone());
    fetcher.add_entity_config_with_jws(
        first_ta_id,
        first_chain.anchor_config.clone(),
        first_chain.anchor_config_jws.clone(),
    );
    fetcher.add_subordinate_stmt_with_jws(
        first_ta_id,
        leaf_id,
        first_chain.subordinate_statement.clone(),
        first_chain.subordinate_jws.clone(),
    );
    fetcher.add_entity_config_with_jws(
        second_ta_id,
        second_chain.anchor_config.clone(),
        second_chain.anchor_config_jws.clone(),
    );
    fetcher.add_subordinate_stmt_with_jws(
        second_ta_id,
        leaf_id,
        second_chain.subordinate_statement.clone(),
        second_chain.subordinate_jws.clone(),
    );

    let trust_anchors = vec![
        TrustAnchor {
            entity_id: first_ta_id.to_string(),
            jwks: must_ok(JwkSet::from_value(first_chain.anchor_jwks.clone())),
            metadata_policy: Some(json!({})),
        },
        TrustAnchor {
            entity_id: second_ta_id.to_string(),
            jwks: must_ok(JwkSet::from_value(second_chain.anchor_jwks.clone())),
            metadata_policy: Some(json!({})),
        },
    ];

    (fetcher, trust_anchors, first_chain, second_chain)
}

#[tokio::test]
async fn resolve_cached_fresh_resolution() {
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let signed_chain = signed_direct_chain(ta_id, leaf_id, now);

    let anchor_repo = InMemoryTrustAnchorRepo::new();
    must_ok(anchor_repo.upsert(env_id, ta_id, &signed_chain.anchor_jwks, Some(&json!({}))));

    let chain_cache = InMemoryTrustChainCacheRepo::new();
    let config = FederationCacheConfig::default();

    let mut fetcher = MockFetcher::new();
    fetcher.add_signed_direct_chain(ta_id, leaf_id, &signed_chain);

    let chain = must_ok(resolve_trust_chain_cached(
        leaf_id,
        env_id,
        &anchor_repo,
        &chain_cache,
        &fetcher,
        &config,
        now,
    )
    .await);

    assert_eq!(must_ok(chain.depth()), 1);
    assert_eq!(must_ok(chain.leaf()).iss, leaf_id);

    // Verify it was cached
    let cached = must_ok(chain_cache.get(env_id, leaf_id, ta_id, now));
    assert!(cached.is_some());
}

#[tokio::test]
async fn resolve_cached_fresh_resolution_respects_requested_anchor_order() {
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let first_ta_id = "https://first-ta.example.com";
    let second_ta_id = "https://second-ta.example.com";
    let leaf_id = "https://rp.example.com";
    let (fetcher, trust_anchors, _, _) =
        requested_anchor_order_fixture(first_ta_id, second_ta_id, leaf_id, now);
    let chain_cache = InMemoryTrustChainCacheRepo::new();

    let resolved = must_ok(resolve_trust_chain_jwts_cached_with(
        leaf_id,
        env_id,
        trust_anchors,
        &chain_cache,
        &FederationCacheConfig::default(),
        now,
        |trust_anchors| {
            let fetcher = &fetcher;
            async move { resolve_trust_chain_with_jwts(leaf_id, &trust_anchors, fetcher, now).await }
        },
    )
    .await);

    assert_eq!(resolved.trust_chain.anchor.entity_id, first_ta_id);
}

#[tokio::test]
async fn resolve_cached_requested_anchor_order_prefers_earlier_fresh_over_later_cache() {
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let first_ta_id = "https://first-ta.example.com";
    let second_ta_id = "https://second-ta.example.com";
    let leaf_id = "https://rp.example.com";
    let (fetcher, trust_anchors, _, second_chain) =
        requested_anchor_order_fixture(first_ta_id, second_ta_id, leaf_id, now);
    let chain_cache = InMemoryTrustChainCacheRepo::new();
    must_ok(chain_cache.upsert(
        env_id,
        leaf_id,
        second_ta_id,
        &signed_chain_jwts(&second_chain),
        now + 3600
    ));

    let resolved = must_ok(resolve_trust_chain_jwts_cached_with(
        leaf_id,
        env_id,
        trust_anchors,
        &chain_cache,
        &FederationCacheConfig::default(),
        now,
        |trust_anchors| {
            let fetcher = &fetcher;
            async move { resolve_trust_chain_with_jwts(leaf_id, &trust_anchors, fetcher, now).await }
        },
    )
    .await);

    assert_eq!(resolved.trust_chain.anchor.entity_id, first_ta_id);
}

#[test]
fn resolve_cached_uses_cache() {
    let _guard = raw_json_env_guard();
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let signed_chain = signed_direct_chain(ta_id, leaf_id, now);

    let anchor_repo = InMemoryTrustAnchorRepo::new();
    must_ok(anchor_repo.upsert(env_id, ta_id, &signed_chain.anchor_jwks, Some(&json!({}))));

    // Pre-populate chain cache
    let chain_cache = InMemoryTrustChainCacheRepo::new();
    must_ok(chain_cache.upsert(
        env_id,
        leaf_id,
        ta_id,
        &signed_chain_jwts(&signed_chain),
        now + 3600
    ));

    let config = FederationCacheConfig::default();

    // Empty fetcher — should not be called
    let fetcher = MockFetcher::new();

    let chain = must_ok(block_on_test_future(resolve_trust_chain_cached(
        leaf_id,
        env_id,
        &anchor_repo,
        &chain_cache,
        &fetcher,
        &config,
        now,
    )));

    assert_eq!(must_ok(chain.depth()), 1);
    assert_eq!(must_ok(chain.leaf()).iss, leaf_id);
}

#[test]
fn resolve_cached_revalidates_cached_statement_temporal_bounds() {
    let _guard = raw_json_env_guard();
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let mut expired_signed_chain = signed_direct_chain(ta_id, leaf_id, now);
    expired_signed_chain.leaf_config.exp = now - 120;
    let leaf_key = InMemoryKeyManager::new();
    expired_signed_chain.leaf_config.jwks = Some(federation_jwks_value(&leaf_key));
    expired_signed_chain.leaf_jws =
        sign_entity_statement_for_test(&leaf_key, &expired_signed_chain.leaf_config);
    let fresh_signed_chain = signed_direct_chain(ta_id, leaf_id, now);

    let anchor_repo = InMemoryTrustAnchorRepo::new();
    must_ok(anchor_repo.upsert(
        env_id,
        ta_id,
        &fresh_signed_chain.anchor_jwks,
        Some(&json!({}))
    ));

    let chain_cache = InMemoryTrustChainCacheRepo::new();
    must_ok(chain_cache.upsert(
        env_id,
        leaf_id,
        ta_id,
        &signed_chain_jwts(&expired_signed_chain),
        now + 3600
    ));

    let mut fetcher = MockFetcher::new();
    fetcher.add_signed_direct_chain(ta_id, leaf_id, &fresh_signed_chain);

    let chain = must_ok(block_on_test_future(resolve_trust_chain_cached(
        leaf_id,
        env_id,
        &anchor_repo,
        &chain_cache,
        &fetcher,
        &FederationCacheConfig::default(),
        now,
    )));

    assert!(
        must_ok(chain.leaf()).exp > now,
        "expired cached chain must be rejected before returning a trust chain"
    );
}

#[test]
fn resolve_cached_rejects_cached_chain_continuity_mismatch() {
    let _guard = raw_json_env_guard();
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let mut signed_chain = signed_direct_chain(ta_id, leaf_id, now);
    let anchor_key = InMemoryKeyManager::new();
    signed_chain.anchor_config.jwks = Some(federation_jwks_value(&anchor_key));
    signed_chain.anchor_jwks = federation_jwks_value(&anchor_key);
    signed_chain.anchor_config_jws =
        sign_entity_statement_for_test(&anchor_key, &signed_chain.anchor_config);
    signed_chain.subordinate_statement.iss = "https://evil.example.com".to_string();
    signed_chain.subordinate_jws =
        sign_entity_statement_for_test(&anchor_key, &signed_chain.subordinate_statement);

    let anchor_repo = InMemoryTrustAnchorRepo::new();
    must_ok(anchor_repo.upsert(env_id, ta_id, &signed_chain.anchor_jwks, Some(&json!({}))));

    let chain_cache = InMemoryTrustChainCacheRepo::new();
    must_ok(chain_cache.upsert(
        env_id,
        leaf_id,
        ta_id,
        &signed_chain_jwts(&signed_chain),
        now + 3600
    ));

    let result = block_on_test_future(resolve_trust_chain_cached(
        leaf_id,
        env_id,
        &anchor_repo,
        &chain_cache,
        &MockFetcher::new(),
        &FederationCacheConfig::default(),
        now,
    ));

    assert!(
        result.is_err(),
        "cached trust chains with broken issuer/superior continuity must not be returned"
    );
}

#[test]
fn resolve_cached_rejects_cached_allowed_leaf_entity_types_violation() {
    let _guard = raw_json_env_guard();
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let signed_chain = signed_direct_chain_with_constraints(
        ta_id,
        leaf_id,
        now,
        Some(Constraints {
            max_path_length: None,
            allowed_leaf_entity_types: Some(vec!["openid_provider".to_string()]),
        }),
    );

    let anchor_repo = InMemoryTrustAnchorRepo::new();
    must_ok(anchor_repo.upsert(env_id, ta_id, &signed_chain.anchor_jwks, Some(&json!({}))));

    let chain_cache = InMemoryTrustChainCacheRepo::new();
    must_ok(chain_cache.upsert(
        env_id,
        leaf_id,
        ta_id,
        &signed_chain_jwts(&signed_chain),
        now + 3600
    ));

    let result = block_on_test_future(resolve_trust_chain_cached(
        leaf_id,
        env_id,
        &anchor_repo,
        &chain_cache,
        &MockFetcher::new(),
        &FederationCacheConfig::default(),
        now,
    ));

    assert!(
        result.is_err(),
        "cached trust chains whose allowed_leaf_entity_types reject the leaf must not be returned"
    );
}

#[tokio::test]
async fn resolve_cached_cache_write_expires_at_shortest_statement_exp() {
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let mut signed_chain = signed_direct_chain(ta_id, leaf_id, now);
    signed_chain.leaf_config.exp = now + 120;
    let leaf_key = InMemoryKeyManager::new();
    signed_chain.leaf_config.jwks = Some(federation_jwks_value(&leaf_key));
    signed_chain.leaf_jws = sign_entity_statement_for_test(&leaf_key, &signed_chain.leaf_config);

    let anchor_repo = InMemoryTrustAnchorRepo::new();
    must_ok(anchor_repo.upsert(env_id, ta_id, &signed_chain.anchor_jwks, Some(&json!({}))));
    let chain_cache = InMemoryTrustChainCacheRepo::new();
    let config = FederationCacheConfig {
        trust_chain_cache_ttl: Duration::from_secs(3600),
        ..FederationCacheConfig::default()
    };

    let mut fetcher = MockFetcher::new();
    fetcher.add_signed_direct_chain(ta_id, leaf_id, &signed_chain);

    let chain = must_ok(resolve_trust_chain_cached(
        leaf_id,
        env_id,
        &anchor_repo,
        &chain_cache,
        &fetcher,
        &config,
        now,
    )
    .await);
    assert_eq!(must_ok(chain.leaf()).exp, now + 120);
    assert!(must_ok(chain_cache.get(env_id, leaf_id, ta_id, now + 119)).is_some());
    assert!(must_ok(chain_cache.get(env_id, leaf_id, ta_id, now + 121)).is_none());
}

#[test]
fn trust_chain_cache_expiry_rejects_overflowing_configured_ttl() {
    let now = i64::MAX - 10;
    let chain = vec![sample_entity_config(
        "https://rp.example.com",
        1_700_000_000,
    )];
    let err = must_err(trust_chain_cache_expires_at(
        now,
        Duration::from_secs(60),
        &chain,
    ));

    assert!(matches!(err, FederationError::Validation(_)));
}

#[tokio::test]
async fn resolve_cached_no_trust_anchors() {
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();

    let anchor_repo = InMemoryTrustAnchorRepo::new();
    let chain_cache = InMemoryTrustChainCacheRepo::new();
    let config = FederationCacheConfig::default();
    let fetcher = MockFetcher::new();

    let err = must_err(resolve_trust_chain_cached(
        "https://rp.example.com",
        env_id,
        &anchor_repo,
        &chain_cache,
        &fetcher,
        &config,
        now,
    )
    .await);

    assert!(matches!(err, FederationError::ChainResolution(_)));
}

#[test]
fn resolve_cached_fails_closed_on_invalid_stored_trust_anchor() {
    let _guard = raw_json_env_guard();
    let now = 1_700_000_000_i64;
    let env_id = Uuid::new_v4();
    let bad_ta_id = "https://bad-ta.example.com";
    let good_ta_id = "https://ta.example.com";
    let leaf_id = "https://rp.example.com";
    let signed_chain = signed_direct_chain(good_ta_id, leaf_id, now);

    let anchor_repo = InMemoryTrustAnchorRepo::new();
    must_ok(anchor_repo.upsert(env_id, bad_ta_id, &json!({"not": "jwks"}), None));
    must_ok(anchor_repo.upsert(env_id, good_ta_id, &signed_chain.anchor_jwks, None));

    let chain_cache = InMemoryTrustChainCacheRepo::new();
    must_ok(chain_cache.upsert(
        env_id,
        leaf_id,
        good_ta_id,
        &signed_chain_jwts(&signed_chain),
        now + 3600
    ));

    let err = must_err(block_on_test_future(resolve_trust_chain_cached(
        leaf_id,
        env_id,
        &anchor_repo,
        &chain_cache,
        &MockFetcher::new(),
        &FederationCacheConfig::default(),
        now,
    )));

    assert!(matches!(err, FederationError::Jwk(_)));
}
