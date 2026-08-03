// ── InMemoryEntityCacheRepo ─────────────────────────────────────

#[test]
fn entity_cache_repo_basic() {
    let repo = InMemoryEntityCacheRepo::new();
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;
    let parsed = json!({"iss": "https://rp.example.com", "sub": "https://rp.example.com"});

    // Miss
    let cached = must_ok(repo.get(env_id, "https://rp.example.com", now));
    assert!(cached.is_none());

    // Insert
    must_ok(repo.upsert(
        env_id,
        "https://rp.example.com",
        "eyJhbGciOi...",
        &parsed,
        now + 1800,
    ));

    // Hit
    let cached = must_ok(repo.get(env_id, "https://rp.example.com", now));
    assert!(cached.is_some());
    let entry = must_some(cached);
    assert_eq!(entry.entity_id, "https://rp.example.com");
    assert_eq!(entry.parsed_statement, parsed);

    // Expired
    let cached = must_ok(repo.get(env_id, "https://rp.example.com", now + 1801));
    assert!(cached.is_none());
}

#[test]
fn entity_cache_repo_environment_isolation() {
    let repo = InMemoryEntityCacheRepo::new();
    let env1 = Uuid::new_v4();
    let env2 = Uuid::new_v4();
    let now = 1_700_000_000_i64;
    let parsed = json!({"iss": "https://rp.example.com"});

    must_ok(repo.upsert(env1, "https://rp.example.com", "jws1", &parsed, now + 1800));

    // Different environment should not see this entry
    assert!(must_ok(repo.get(env2, "https://rp.example.com", now)).is_none());
    // Same environment should see it
    assert!(must_ok(repo.get(env1, "https://rp.example.com", now)).is_some());
}

#[test]
fn entity_cache_repo_upsert_overwrites() {
    let repo = InMemoryEntityCacheRepo::new();
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;

    must_ok(repo.upsert(
        env_id,
        "https://rp.example.com",
        "jws-v1",
        &json!({"version": 1}),
        now + 1800,
    ));

    must_ok(repo.upsert(
        env_id,
        "https://rp.example.com",
        "jws-v2",
        &json!({"version": 2}),
        now + 3600,
    ));

    let cached = must_some(must_ok(repo.get(env_id, "https://rp.example.com", now)));
    assert_eq!(cached.entity_configuration_jws, "jws-v2");
    assert_eq!(cached.parsed_statement, json!({"version": 2}));
}

#[test]
fn entity_cache_repo_cleanup_expired() {
    let repo = InMemoryEntityCacheRepo::new();
    let env_id = Uuid::new_v4();
    let now = 1_700_000_000_i64;

    must_ok(repo.upsert(
        env_id,
        "https://e1.example.com",
        "j1",
        &json!({}),
        now + 100,
    ));
    must_ok(repo.upsert(
        env_id,
        "https://e2.example.com",
        "j2",
        &json!({}),
        now + 200,
    ));
    must_ok(repo.upsert(
        env_id,
        "https://e3.example.com",
        "j3",
        &json!({}),
        now + 300,
    ));

    // Cleanup at now+150 should remove e1 only
    let removed = must_ok(repo.cleanup_expired(now + 150));
    assert_eq!(removed, 1);

    // e2 and e3 should still be present
    assert!(must_ok(repo.get(env_id, "https://e2.example.com", now + 150)).is_some());
    assert!(must_ok(repo.get(env_id, "https://e3.example.com", now + 150)).is_some());
}
