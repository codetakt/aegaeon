// ── P8-CACHE-1: LRU eviction ───────────────────────────────────

#[test]
fn entity_cache_lru_eviction() {
    let repo = InMemoryEntityCacheRepo::new().with_max_entries(2);
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;

    // Insert entry 1
    must_ok(repo.upsert(
        env_id,
        "https://e1.example.com",
        "j1",
        &json!({"v": 1}),
        now + 3600,
    ));
    // Insert entry 2
    must_ok(repo.upsert(
        env_id,
        "https://e2.example.com",
        "j2",
        &json!({"v": 2}),
        now + 3600,
    ));

    // Both should be present
    assert!(must_ok(repo.get(env_id, "https://e1.example.com", now)).is_some());
    assert!(must_ok(repo.get(env_id, "https://e2.example.com", now)).is_some());

    // Insert entry 3 — should evict the oldest (entry 1, since it was fetched first)
    must_ok(repo.upsert(
        env_id,
        "https://e3.example.com",
        "j3",
        &json!({"v": 3}),
        now + 3600,
    ));

    // entry 1 should have been evicted (oldest fetched_at)
    assert!(must_ok(repo.get(env_id, "https://e1.example.com", now)).is_none());
    // entry 2 and 3 should still be present
    assert!(must_ok(repo.get(env_id, "https://e2.example.com", now)).is_some());
    assert!(must_ok(repo.get(env_id, "https://e3.example.com", now)).is_some());
}

#[test]
fn entity_cache_upsert_does_not_evict() {
    let repo = InMemoryEntityCacheRepo::new().with_max_entries(2);
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;

    must_ok(repo.upsert(
        env_id,
        "https://e1.example.com",
        "j1",
        &json!({"v": 1}),
        now + 3600,
    ));
    must_ok(repo.upsert(
        env_id,
        "https://e2.example.com",
        "j2",
        &json!({"v": 2}),
        now + 3600,
    ));

    // Upsert (update) an existing entry — should NOT evict
    must_ok(repo.upsert(
        env_id,
        "https://e1.example.com",
        "j1-v2",
        &json!({"v": 11}),
        now + 7200,
    ));

    // Both still present
    assert!(must_ok(repo.get(env_id, "https://e1.example.com", now)).is_some());
    assert!(must_ok(repo.get(env_id, "https://e2.example.com", now)).is_some());

    let e1 = must_some(must_ok(repo.get(env_id, "https://e1.example.com", now)));
    assert_eq!(e1.entity_configuration_jws, "j1-v2");
}

#[test]
fn trust_chain_cache_lru_eviction() {
    let repo = InMemoryTrustChainCacheRepo::new().with_max_entries(2);
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;

    must_ok(repo.upsert(env_id, "leaf1", "ta1", &json!(["chain1"]), now + 3600));
    must_ok(repo.upsert(env_id, "leaf2", "ta2", &json!(["chain2"]), now + 3600));

    assert!(must_ok(repo.get(env_id, "leaf1", "ta1", now)).is_some());
    assert!(must_ok(repo.get(env_id, "leaf2", "ta2", now)).is_some());

    // Insert third — evicts oldest (leaf1/ta1)
    must_ok(repo.upsert(env_id, "leaf3", "ta3", &json!(["chain3"]), now + 3600));

    assert!(must_ok(repo.get(env_id, "leaf1", "ta1", now)).is_none());
    assert!(must_ok(repo.get(env_id, "leaf2", "ta2", now)).is_some());
    assert!(must_ok(repo.get(env_id, "leaf3", "ta3", now)).is_some());
}

#[test]
fn trust_chain_cache_upsert_does_not_evict() {
    let repo = InMemoryTrustChainCacheRepo::new().with_max_entries(2);
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;

    must_ok(repo.upsert(env_id, "leaf1", "ta1", &json!(["chain1"]), now + 3600));
    must_ok(repo.upsert(env_id, "leaf2", "ta2", &json!(["chain2"]), now + 3600));

    // Update existing — no eviction
    must_ok(repo.upsert(env_id, "leaf1", "ta1", &json!(["chain1-v2"]), now + 7200));

    assert!(must_ok(repo.get(env_id, "leaf1", "ta1", now)).is_some());
    assert!(must_ok(repo.get(env_id, "leaf2", "ta2", now)).is_some());
}

#[test]
fn cache_max_entries_default() {
    let entity_repo = InMemoryEntityCacheRepo::new();
    assert_eq!(entity_repo.max_entries, DEFAULT_FEDERATION_CACHE_MAX_ENTRIES);

    let chain_repo = InMemoryTrustChainCacheRepo::new();
    assert_eq!(chain_repo.max_entries, DEFAULT_FEDERATION_CACHE_MAX_ENTRIES);
}
