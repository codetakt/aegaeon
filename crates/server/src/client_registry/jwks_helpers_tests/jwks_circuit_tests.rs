use super::*;

fn cache_entry_with_fetch_age(age: std::time::Duration) -> CacheEntry {
    let jwks = FetchedJwks {
        keys: vec![FetchedJwk {
            kty: "RSA".into(),
            key_use: None,
            key_ops: None,
            kid: Some("cache-key".into()),
            alg: Some("RS256".into()),
            n: Some("00".into()),
            e: Some("AQAB".into()),
            x: None,
            y: None,
            crv: None,
        }],
    };
    cache_test_entry(jwks, std::time::Instant::now() - age)
}

fn insert_open_circuit(state: &JwksRuntimeState, uri: &str) {
    let mut circuits = state
        .inner
        .coordination
        .circuits
        .lock()
        .expect("test circuit state lock should not be poisoned");
    circuits.insert(
        uri.to_string(),
        CircuitState {
            phase: CircuitPhase::Open,
            consecutive_failures: 1,
            opened_at: Some(std::time::Instant::now()),
            probe_in_flight: false,
        },
    );
}

#[test]
fn fresh_memory_cache_hit_is_allowed_while_fetch_circuit_is_open() {
    let uri = "https://example.com/fresh-memory-hit-jwks.json";
    let state = JwksRuntimeState::default();
    let policy = JwksRuntimePolicy {
        cache_ttl_secs: 300,
        circuit_reset_secs: 60,
        ..JwksRuntimePolicy::default()
    };
    insert_open_circuit(&state, uri);
    {
        let mut cache = state
            .inner
            .cache
            .lock()
            .expect("test cache lock should not be poisoned");
        cache.insert(
            uri.to_string(),
            cache_entry_with_fetch_age(std::time::Duration::from_secs(10)),
        );
    }

    let jwks = fetch_jwks_with_state(&state, &policy, uri)
        .expect("fresh positive memory cache entry should be served");

    assert_eq!(jwks.keys.len(), 1);
    assert!(matches!(
        circuit_phase_with_state(&state, uri),
        CircuitPhase::Open
    ));
}

#[test]
fn expired_memory_cache_entry_does_not_bypass_open_fetch_circuit() {
    let uri = "https://example.com/expired-memory-hit-jwks.json";
    let state = JwksRuntimeState::default();
    let policy = JwksRuntimePolicy {
        cache_ttl_secs: 1,
        circuit_reset_secs: 60,
        ..JwksRuntimePolicy::default()
    };
    insert_open_circuit(&state, uri);
    {
        let mut cache = state
            .inner
            .cache
            .lock()
            .expect("test cache lock should not be poisoned");
        let mut entry = cache_entry_with_fetch_age(std::time::Duration::from_secs(30));
        // This fixture represents acquisition under this case's one-second
        // default, not the common helper's separate 300-second policy.
        entry.freshness.lifetime = Some(1_000_000_000);
        cache.insert(uri.to_string(), entry);
    }

    assert!(
        fetch_jwks_with_state(&state, &policy, uri).is_none(),
        "expired memory body must not act as stale-if-error fallback"
    );
    assert!(matches!(
        circuit_phase_with_state(&state, uri),
        CircuitPhase::Open
    ));
}

fn assert_expired_cache_rejected_after_refresh_url_refusal(entry: CacheEntry) {
    // This literal is rejected before DNS, client construction, or network I/O.
    let uri = "https://127.0.0.1/jwks.json";
    let state = JwksRuntimeState::default();
    let policy = JwksRuntimePolicy {
        cache_ttl_secs: 300,
        cache_gc_interval_secs: 600,
        circuit_open_fails: 1,
        ..JwksRuntimePolicy::default()
    };
    assert_eq!(
        super::super::jwks_url::validate_jwks_fetch_url(&policy, uri),
        Err("jwks_uri must not target non-routable hosts".to_string())
    );
    let last_gc = std::time::Instant::now();
    *state.inner.last_gc.lock().expect("test GC lock") = Some(last_gc);
    let fetched_at = entry.fetched_at;
    let lifetime = entry.freshness.lifetime;
    state
        .inner
        .cache
        .lock()
        .expect("test cache lock")
        .insert(uri.to_string(), entry);
    assert!(matches!(
        circuit_phase_with_state(&state, uri),
        CircuitPhase::Closed
    ));

    let fetched = fetch_jwks_with_state(&state, &policy, uri);

    // A real refresh failure increments this count and opens the circuit. An
    // initial cache hit or pre-refresh circuit refusal cannot satisfy these.
    {
        let circuits = state
            .inner
            .coordination
            .circuits
            .lock()
            .expect("test circuit lock");
        let circuit = circuits.get(uri).expect("refresh created circuit state");
        assert_eq!(circuit.consecutive_failures, 1);
        assert!(matches!(circuit.phase, CircuitPhase::Open));
    }
    assert_eq!(
        *state.inner.last_gc.lock().expect("test GC lock"),
        Some(last_gc),
        "GC must have been skipped"
    );
    {
        let cache = state.inner.cache.lock().expect("test cache lock");
        let retained = cache.get(uri).expect("expired body must remain in cache");
        assert_eq!(retained.fetched_at, fetched_at);
        assert_eq!(retained.freshness.lifetime, lifetime);
    }
    assert!(
        fetched.is_none(),
        "expired retained body must not be returned after an admitted refresh fails"
    );
}

#[test]
fn explicit_expiry_rejects_cache_after_refresh_url_refusal() {
    let mut entry = cache_entry_with_fetch_age(std::time::Duration::ZERO);
    fixture_fresh_for(&mut entry, std::time::Duration::ZERO);
    assert_expired_cache_rejected_after_refresh_url_refusal(entry);
}

#[test]
fn fallback_ttl_rejects_cache_after_refresh_url_refusal() {
    assert_expired_cache_rejected_after_refresh_url_refusal(cache_entry_with_fetch_age(
        std::time::Duration::from_secs(301),
    ));
}

#[test]
fn half_open_allows_only_one_probe_until_result() {
    let uri = "https://example.com/single-probe-jwks.json";
    let policy = JwksRuntimePolicy::default();
    if let Ok(mut circuits) = jwks_runtime_state().inner.coordination.circuits.lock() {
        circuits.insert(
            uri.to_string(),
            CircuitState {
                phase: CircuitPhase::HalfOpen,
                consecutive_failures: 1,
                opened_at: None,
                probe_in_flight: false,
            },
        );
    }

    assert!(circuit_allow_fetch(&policy, uri));
    assert!(!circuit_allow_fetch(&policy, uri));

    circuit_on_failure(&policy, uri);
    assert!(matches!(circuit_phase(uri), CircuitPhase::Open));

    if let Ok(mut circuits) = jwks_runtime_state().inner.coordination.circuits.lock() {
        circuits.insert(
            uri.to_string(),
            CircuitState {
                phase: CircuitPhase::HalfOpen,
                consecutive_failures: 1,
                opened_at: None,
                probe_in_flight: false,
            },
        );
    }
    assert!(circuit_allow_fetch(&policy, uri));

    circuit_on_success(uri);
    assert!(matches!(circuit_phase(uri), CircuitPhase::Closed));
    assert!(circuit_allow_fetch(&policy, uri));

    if let Ok(mut circuits) = jwks_runtime_state().inner.coordination.circuits.lock() {
        circuits.remove(uri);
    }
}

#[test]
fn half_open_malformed_jwks_body_reopens_circuit() {
    let uri = "https://example.com/malformed-jwks.json";
    let uri_hash = &sha256_hex(uri.as_bytes())[0..8];
    let policy = JwksRuntimePolicy::default();

    if let Ok(mut circuits) = jwks_runtime_state().inner.coordination.circuits.lock() {
        circuits.insert(
            uri.to_string(),
            CircuitState {
                phase: CircuitPhase::HalfOpen,
                consecutive_failures: 1,
                opened_at: None,
                probe_in_flight: true,
            },
        );
    }

    assert!(decode_fetched_jwks_body(
        &policy,
        uri,
        uri_hash,
        b"not-json",
        std::time::Instant::now()
    )
    .is_none());
    assert!(matches!(circuit_phase(uri), CircuitPhase::Open));

    if let Ok(mut cache) = jwks_runtime_state().inner.cache.lock() {
        cache.remove(uri);
    }
    if let Ok(mut circuits) = jwks_runtime_state().inner.coordination.circuits.lock() {
        circuits.remove(uri);
    }
}
