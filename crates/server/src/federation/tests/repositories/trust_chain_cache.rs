// ── InMemoryTrustChainCacheRepo ─────────────────────────────────

#[test]
fn trust_chain_cache_basic() {
    let repo = InMemoryTrustChainCacheRepo::new();
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;
    let chain_jwts = json!(["jwt1", "jwt2", "jwt3"]);

    // Miss
    assert!(must_ok(repo.get(
        env_id,
        "https://rp.example.com",
        "https://ta.example.com",
        now
    ))
    .is_none());

    // Insert
    must_ok(repo.upsert(
        env_id,
        "https://rp.example.com",
        "https://ta.example.com",
        &chain_jwts,
        now + 3600,
    ));

    // Hit
    let cached = must_ok(repo.get(
        env_id,
        "https://rp.example.com",
        "https://ta.example.com",
        now,
    ));
    assert!(cached.is_some());
    assert_eq!(must_some(cached).chain_jwts, chain_jwts);

    // Expired
    assert!(must_ok(repo.get(
        env_id,
        "https://rp.example.com",
        "https://ta.example.com",
        now + 3601
    ))
    .is_none());
}

#[test]
fn trust_chain_cache_environment_isolation() {
    let repo = InMemoryTrustChainCacheRepo::new();
    let env1 = Uuid::new_v4();
    let env2 = Uuid::new_v4();
    let now = 1_700_000_000_i64;

    must_ok(repo.upsert(
        env1,
        "https://rp.example.com",
        "https://ta.example.com",
        &json!(["chain1"]),
        now + 3600,
    ));

    // env2 should not see env1's chain
    assert!(must_ok(repo.get(
        env2,
        "https://rp.example.com",
        "https://ta.example.com",
        now
    ))
    .is_none());
}

#[test]
fn trust_chain_cache_cleanup_expired() {
    let repo = InMemoryTrustChainCacheRepo::new();
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;

    must_ok(repo.upsert(env_id, "leaf1", "ta1", &json!([]), now + 100));
    must_ok(repo.upsert(env_id, "leaf2", "ta2", &json!([]), now + 200));

    let removed = must_ok(repo.cleanup_expired(now + 150));
    assert_eq!(removed, 1);

    assert!(must_ok(repo.get(env_id, "leaf1", "ta1", now + 150)).is_none());
    assert!(must_ok(repo.get(env_id, "leaf2", "ta2", now + 150)).is_some());
}
