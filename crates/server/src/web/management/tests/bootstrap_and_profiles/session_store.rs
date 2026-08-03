
// ---------------------------------------------------------------
// P0: ManagementSessionStore unit tests
// ---------------------------------------------------------------

#[test]
fn session_store_create_and_get() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(3600);
    let admin_id = Uuid::new_v4();
    let now = 1_000_000u64;
    let sid = must_some!(store.create(admin_id, now), "session created");

    let session = store
        .get(&sid, now)
        .ok_or_else(|| io::Error::other("session should exist"))?;
    assert_eq!(session.administrator_id, admin_id);
    Ok(())
}

#[test]
fn session_store_try_create_reports_backend_unavailable() -> TestResult {
    let store = redis_management_session_store_for_test("redis://127.0.0.1:1/", "management-down")?;

    assert!(store.try_create(Uuid::new_v4(), 1_000_000).is_err());
    assert!(store.create(Uuid::new_v4(), 1_000_000).is_none());
    Ok(())
}

fn redis_management_session_store_for_test(
    url: &str,
    key: &str,
) -> Result<ManagementSessionStore, Box<dyn StdError>> {
    Ok(ManagementSessionStore {
        backend: ManagementSessionBackend::Redis(RedisManagementSessionBackend::new_with_key(
            url,
            Arc::<str>::from(key.to_string()),
        )?),
        session_ttl_secs: 60,
        max_sessions: 10,
    })
}

fn clear_redis_management_session_store_for_test(url: &str, key: &str) -> redis::RedisResult<()> {
    let client = redis::Client::open(url)?;
    let mut conn = client.get_connection()?;
    let keyspace = RedisManagementSessionKeyspace::from_prefix(Arc::<str>::from(key.to_string()));
    let keys = redis::cmd("KEYS")
        .arg(format!("{}:*", keyspace.prefix))
        .query::<Vec<String>>(&mut conn)?;
    if !keys.is_empty() {
        redis::cmd("DEL").arg(keys).query::<usize>(&mut conn)?;
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_management_session_store_shares_create_get_delete() -> TestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "management-session-test:v2:{{{}}}",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_management_session_store_for_test(url.trim(), &key)?;
    let store_a = redis_management_session_store_for_test(url.trim(), &key)?;
    let store_b = redis_management_session_store_for_test(url.trim(), &key)?;
    let admin_id = Uuid::new_v4();
    let sid = store_a
        .create(admin_id, 1_000_000)
        .ok_or_else(|| io::Error::other("session should be created"))?;

    assert_eq!(
        store_b
            .try_get(&sid, 1_000_001)
            .map_err(io::Error::other)?
            .map(|session| session.administrator_id),
        Some(admin_id)
    );
    assert!(
        store_b.try_delete(&sid).map_err(io::Error::other)?,
        "redis-backed delete should remove the session"
    );
    assert!(store_a
        .try_get(&sid, 1_000_002)
        .map_err(io::Error::other)?
        .is_none());
    Ok(())
}

#[test]
fn session_store_try_get_unknown_sid_returns_none() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(3600);
    assert!(store
        .try_get("nonexistent-sid", 1_000_000)
        .map_err(io::Error::other)?
        .is_none());
    Ok(())
}

#[test]
fn session_store_delete_removes_session() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(3600);
    let sid = must_some!(store.create(Uuid::new_v4(), 1_000_000), "session created");
    assert!(must_ok!(
        store.try_delete(&sid),
        "in-memory delete should be confirmed"
    ));
    assert!(store.get(&sid, 1_000_000).is_none());
    Ok(())
}

#[test]
fn session_store_ttl_before_expiry_valid() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(60);
    let sid = must_some!(store.create(Uuid::new_v4(), 1000), "session created");
    // 59 seconds later — still valid (59 < 60)
    assert!(store.get(&sid, 1059).is_some());
    Ok(())
}

#[test]
fn session_store_ttl_at_boundary_expired() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(60);
    let sid = must_some!(store.create(Uuid::new_v4(), 1000), "session created");
    // Exactly 60 seconds later — expired (>= ttl)
    assert!(store.get(&sid, 1060).is_none());
    Ok(())
}

#[test]
fn session_store_ttl_after_expiry_expired() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(60);
    let sid = must_some!(store.create(Uuid::new_v4(), 1000), "session created");
    // 61 seconds later — expired
    assert!(store.get(&sid, 1061).is_none());
    Ok(())
}

#[test]
fn session_store_rejects_future_created_session() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(60);
    let sid = must_some!(store.create(Uuid::new_v4(), 2000), "session created");

    assert!(store.get(&sid, 1999).is_none());
    let map = store
        .in_memory_sessions()
        .read()
        .map_err(|_| io::Error::other("session lock poisoned"))?;
    assert!(!map.contains_key(&sid));
    Ok(())
}

#[test]
fn session_store_ttl_and_capacity_are_bounded() {
    let store = ManagementSessionStore::new_process_local_with_limits(u64::MAX, 0);

    assert_eq!(store.session_ttl_secs, MAX_SESSION_TTL_SECS);
    assert_eq!(store.max_sessions, 1);
}

#[test]
fn session_store_missing_redis_configuration_fails_closed() -> TestResult {
    let _guard = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|_| "server env guard".to_string())?;
    let _session_redis = EnvVarGuard::unset("AEGAEON_MANAGEMENT_SESSION_REDIS_URL");

    let err = must_err!(
        ManagementSessionStore::try_from_config(
            &test_management_config(),
            &crate::config::RuntimeStateNamespace::for_tests("management-session-test"),
        ),
        "management sessions must require a shared store"
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_MANAGEMENT_SESSION_REDIS_URL"
                && reason.contains("management session store")
                && reason.contains("DB/Redis-backed shared runtime state")
    ));
    Ok(())
}

#[test]
fn session_store_create_rejects_unrepresentable_expiry() {
    let store = ManagementSessionStore::new_process_local_with_limits(3600, 10);

    assert!(store.create(Uuid::new_v4(), u64::MAX).is_none());
}

#[test]
fn session_store_expired_session_is_lazily_removed() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(10);
    let sid = must_some!(store.create(Uuid::new_v4(), 100), "session created");
    // Access after expiry triggers lazy removal
    assert!(store.get(&sid, 111).is_none());
    // Confirm it's actually removed from the map
    let map = store
        .in_memory_sessions()
        .read()
        .map_err(|_| io::Error::other("session lock poisoned"))?;
    assert!(!map.contains_key(&sid));
    Ok(())
}

#[test]
fn session_store_multiple_sessions_independent() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(100);
    let sid1 = must_some!(store.create(Uuid::new_v4(), 1000), "session created");
    let sid2 = must_some!(store.create(Uuid::new_v4(), 1050), "session created");

    // At t=1099: sid1 is 99s old (valid), sid2 is 49s old (valid)
    assert!(store.get(&sid1, 1099).is_some());
    assert!(store.get(&sid2, 1099).is_some());

    // At t=1100: sid1 is 100s old (expired), sid2 is 50s old (valid)
    assert!(store.get(&sid1, 1100).is_none());
    assert!(store.get(&sid2, 1100).is_some());
    Ok(())
}
