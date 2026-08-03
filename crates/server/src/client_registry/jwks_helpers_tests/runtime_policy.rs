use super::*;

#[test]
fn seeded_test_clients_require_test_or_explicit_helper_build() -> TestResult {
    let err = test_err(
        test_clients_allowed_by_build(false),
        "release builds must reject seeded test clients",
    )?;

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, .. } if key == SEEDED_TEST_CLIENTS_BUILD_GUARD
    ));
    assert_eq!(
        test_clients_allowed_by_build(true),
        Ok(()),
        "tests may seed deterministic test clients"
    );
    Ok(())
}

#[test]
fn jwks_runtime_knob_bounds_are_finite() {
    assert!(!valid_jwks_cache_ttl_secs(0));
    assert!(valid_jwks_cache_ttl_secs(MAX_JWKS_CACHE_TTL_SECS));
    assert!(!valid_jwks_cache_ttl_secs(MAX_JWKS_CACHE_TTL_SECS + 1));

    assert!(!valid_jwks_cache_gc_interval_secs(0));
    assert!(valid_jwks_cache_gc_interval_secs(
        MAX_JWKS_CACHE_GC_INTERVAL_SECS
    ));
    assert!(!valid_jwks_cache_gc_interval_secs(
        MAX_JWKS_CACHE_GC_INTERVAL_SECS + 1
    ));

    assert!(!valid_jwks_http_timeout_secs(0));
    assert!(valid_jwks_http_timeout_secs(MAX_JWKS_HTTP_TIMEOUT_SECS));
    assert!(!valid_jwks_http_timeout_secs(
        MAX_JWKS_HTTP_TIMEOUT_SECS + 1
    ));

    assert!(!valid_jwks_circuit_reset_secs(0));
    assert!(valid_jwks_circuit_reset_secs(MAX_JWKS_CIRCUIT_RESET_SECS));
    assert!(!valid_jwks_circuit_reset_secs(
        MAX_JWKS_CIRCUIT_RESET_SECS + 1
    ));

    assert!(valid_jwks_refresh_skew_secs(0));
    assert!(valid_jwks_refresh_skew_secs(MAX_JWKS_REFRESH_SKEW_SECS));
    assert!(!valid_jwks_refresh_skew_secs(
        MAX_JWKS_REFRESH_SKEW_SECS + 1
    ));

    assert!(valid_jwks_http_retries(0));
    assert!(valid_jwks_http_retries(MAX_JWKS_HTTP_RETRIES));
    assert!(!valid_jwks_http_retries(MAX_JWKS_HTTP_RETRIES + 1));

    assert_eq!(
        JwksRuntimePolicy::default().local_cache_max_entries,
        DEFAULT_JWKS_LOCAL_CACHE_MAX_ENTRIES
    );
    assert!(valid_jwks_local_cache_max_entries(1));
    assert!(valid_jwks_local_cache_max_entries(
        MAX_JWKS_LOCAL_CACHE_MAX_ENTRIES
    ));
    assert!(!valid_jwks_local_cache_max_entries(0));
    assert!(!valid_jwks_local_cache_max_entries(
        MAX_JWKS_LOCAL_CACHE_MAX_ENTRIES + 1
    ));
}

#[test]
fn jwks_process_local_cache_pruning_evicts_oldest_entries() {
    let now = std::time::Instant::now();
    let mut cache = HashMap::from([
        (
            "old".to_string(),
            test_cache_entry(now - std::time::Duration::from_secs(30)),
        ),
        (
            "middle".to_string(),
            test_cache_entry(now - std::time::Duration::from_secs(20)),
        ),
        (
            "new".to_string(),
            test_cache_entry(now - std::time::Duration::from_secs(10)),
        ),
    ]);

    jwks_gc::prune_cache_to_capacity(&mut cache, 2);

    assert_eq!(cache.len(), 2);
    assert!(!cache.contains_key("old"));
    assert!(cache.contains_key("middle"));
    assert!(cache.contains_key("new"));
}

#[test]
fn jwks_fetch_coordination_prunes_idle_locks_and_rejects_capacity_overflow() -> TestResult {
    let state = JwksRuntimeState::default();
    let active_a = test_some(
        test_context(
            state
                .inner
                .coordination
                .fetch_lock(2, "https://a.example/jwks"),
            "fetch lock a",
        )?,
        "fetch lock a should be admitted",
    )?;
    let idle_b = test_some(
        test_context(
            state
                .inner
                .coordination
                .fetch_lock(2, "https://b.example/jwks"),
            "fetch lock b",
        )?,
        "fetch lock b should be admitted",
    )?;
    drop(idle_b);

    let active_c = test_some(
        test_context(
            state
                .inner
                .coordination
                .fetch_lock(2, "https://c.example/jwks"),
            "fetch lock c",
        )?,
        "fetch lock c should prune idle b and be admitted",
    )?;

    {
        let locks = test_lock(
            state.inner.coordination.fetch_locks.lock(),
            "JWKS fetch locks should not be poisoned",
        )?;
        assert_eq!(locks.len(), 2);
        assert!(locks.contains_key("https://a.example/jwks"));
        assert!(locks.contains_key("https://c.example/jwks"));
        assert!(!locks.contains_key("https://b.example/jwks"));
    }

    assert!(
        test_context(
            state
                .inner
                .coordination
                .fetch_lock(2, "https://d.example/jwks"),
            "fetch lock d",
        )?
        .is_none(),
        "new URI coordination must be refused when all retained locks are active"
    );

    drop(active_a);
    drop(active_c);
    Ok(())
}

#[test]
fn jwks_background_refresh_coordination_is_capacity_bounded() -> TestResult {
    let state = JwksRuntimeState::default();

    assert!(test_context(
        state
            .inner
            .coordination
            .mark_background_refresh_started(1, "https://a.example/jwks"),
        "background refresh a",
    )?);
    assert!(
        !test_context(
            state
                .inner
                .coordination
                .mark_background_refresh_started(1, "https://b.example/jwks"),
            "background refresh b",
        )?,
        "new background refresh must be refused at capacity"
    );

    test_context(
        state
            .inner
            .coordination
            .mark_background_refresh_finished("https://a.example/jwks"),
        "background refresh cleanup",
    )?;
    assert!(test_context(
        state
            .inner
            .coordination
            .mark_background_refresh_started(1, "https://b.example/jwks"),
        "background refresh b after cleanup",
    )?);
    Ok(())
}

fn test_cache_entry(fetched_at: std::time::Instant) -> CacheEntry {
    CacheEntry {
        etag: None,
        expires_at: None,
        fetched_at,
        jwks: FetchedJwks { keys: Vec::new() },
        kid_fps: HashMap::new(),
        last_modified: None,
    }
}

#[test]
fn jwks_fetch_uses_injected_runtime_state() -> TestResult {
    let uri = "https://127.0.0.1/jwks.json";
    let state_with_cache = JwksRuntimeState::default();
    let empty_state = JwksRuntimeState::default();
    let policy = JwksRuntimePolicy {
        http_retries: 0,
        ..JwksRuntimePolicy::default()
    };
    let jwks = FetchedJwks {
        keys: vec![FetchedJwk {
            kty: "RSA".to_string(),
            key_use: Some("sig".to_string()),
            key_ops: None,
            kid: Some("k1".to_string()),
            alg: Some("RS256".to_string()),
            n: Some("AQAB".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        }],
    };

    test_lock(
        state_with_cache.inner.cache.lock(),
        "JWKS cache should not be poisoned",
    )?
    .insert(
        uri.to_string(),
        CacheEntry {
            etag: None,
            expires_at: None,
            fetched_at: std::time::Instant::now(),
            jwks,
            kid_fps: HashMap::new(),
            last_modified: None,
        },
    );

    assert!(fetch_jwks_with_state(&state_with_cache, &policy, uri).is_some());
    assert!(fetch_jwks_with_state(&empty_state, &policy, uri).is_none());
    Ok(())
}

#[test]
fn jwks_background_refresh_is_singleflight_by_uri() -> TestResult {
    let _lock = env_lock()?;
    let uri = "https://jwks.example/singleflight";

    {
        let mut refreshes = test_lock(
            jwks_runtime_state()
                .inner
                .coordination
                .background_refreshes
                .lock(),
            "JWKS refresh set should not be poisoned",
        )?;
        refreshes.remove(uri);
        refreshes.insert(uri.to_string());
    }

    spawn_jwks_refresh_once(JwksRuntimePolicy::default(), uri, None, None);

    let still_in_flight = test_lock(
        jwks_runtime_state()
            .inner
            .coordination
            .background_refreshes
            .lock(),
        "JWKS refresh set should not be poisoned",
    )?
    .contains(uri);
    assert!(still_in_flight);

    test_lock(
        jwks_runtime_state()
            .inner
            .coordination
            .background_refreshes
            .lock(),
        "JWKS refresh set should not be poisoned",
    )?
    .remove(uri);
    Ok(())
}

#[test]
fn jwks_fetch_url_rejects_ssrf_and_credential_shapes() -> TestResult {
    for uri in [
        "http://example.com/jwks.json",
        "https://127.0.0.1/jwks.json",
        "https://localhost/jwks.json",
        "https://10.0.0.1/jwks.json",
        "https://[fc00::1]/jwks.json",
        "https://user@example.com/jwks.json",
        "https://example.com/jwks.json#fragment",
    ] {
        let err = test_err(
            validate_jwks_fetch_url(&JwksRuntimePolicy::default(), uri),
            "unsafe jwks_uri must be rejected",
        )?;
        assert!(
            err.contains("jwks_uri"),
            "unexpected error for {uri}: {err}"
        );
    }
    Ok(())
}

#[test]
fn jwks_loopback_override_is_test_build_only_and_shape_limited() {
    let policy = JwksRuntimePolicy {
        allow_http_loopback_for_tests: true,
        ..JwksRuntimePolicy::default()
    };

    assert_eq!(
        jwks_http_loopback_allowed_for_tests(&policy, "http://127.0.0.1/jwks.json"),
        cfg!(test)
    );
    assert_eq!(
        jwks_http_loopback_allowed_for_tests(&policy, "http://[::1]/jwks.json"),
        cfg!(test)
    );
    assert!(!jwks_http_loopback_allowed_for_tests(
        &policy,
        "http://example.com/jwks.json"
    ));
    assert!(!jwks_http_loopback_allowed_for_tests(
        &policy,
        "https://127.0.0.1/jwks.json"
    ));
    assert!(!jwks_http_loopback_allowed_for_tests(
        &policy,
        "http://127.0.0.1/jwks.json#fragment"
    ));
    assert!(!jwks_http_loopback_allowed_for_tests(
        &policy,
        "http://user@127.0.0.1/jwks.json"
    ));
}

#[test]
fn jwks_insecure_skip_verify_is_test_loopback_only() {
    let policy = JwksRuntimePolicy {
        allow_http_loopback_for_tests: true,
        insecure_skip_verify: true,
        ..JwksRuntimePolicy::default()
    };

    assert!(
        !jwks_insecure_skip_verify_allowed(&policy, "https://example.com/jwks.json"),
        "production-shaped HTTPS JWKS fetches must not disable certificate verification"
    );
    assert_eq!(
        jwks_insecure_skip_verify_allowed(&policy, "http://127.0.0.1/jwks.json"),
        cfg!(test)
    );
    assert_eq!(
        jwks_insecure_skip_verify_allowed(&policy, "http://[::1]/jwks.json"),
        cfg!(test)
    );
}
