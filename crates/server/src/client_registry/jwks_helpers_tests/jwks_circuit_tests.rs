use super::super::jwks_validation::build_kid_fingerprints;
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
    CacheEntry {
        etag: Some("test-etag".into()),
        expires_at: None,
        fetched_at: std::time::Instant::now() - age,
        kid_fps: build_kid_fingerprints(&jwks),
        last_modified: Some("Wed, 01 Jul 2026 00:00:00 GMT".into()),
        jwks,
    }
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
        cache.insert(
            uri.to_string(),
            cache_entry_with_fetch_age(std::time::Duration::from_secs(30)),
        );
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
