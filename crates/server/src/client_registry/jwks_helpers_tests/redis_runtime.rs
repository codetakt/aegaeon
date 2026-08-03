use super::*;

fn test_jwks_redis_url() -> Option<String> {
    std::env::var("AEGAEON_TEST_REDIS_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn redis_jwks_runtime_state(url: &str) -> Result<JwksRuntimeState, String> {
    test_context(
        RedisJwksRuntimeState::new_for_tests(url),
        "valid JWKS Redis runtime state URL",
    )
    .map(JwksSharedRuntimeState::Redis)
    .map(JwksRuntimeState::with_shared_state)
}

fn clear_jwks_redis_keys(url: &str, uri: &str) -> TestResult {
    let client = test_context(redis::Client::open(url), "valid Redis test URL")?;
    let state = test_context(
        RedisJwksRuntimeState::new_for_tests(url),
        "valid JWKS Redis runtime state URL",
    )?;
    let mut conn = test_context(
        client.get_connection(),
        "Redis test connection should be available",
    )?;
    for kind in ["circuit", "kid-fps"] {
        let deleted: redis::RedisResult<i32> =
            redis::cmd("DEL").arg(state.key(kind, uri)).query(&mut conn);
        test_context(deleted, "JWKS Redis test key cleanup should succeed")?;
    }
    Ok(())
}

fn unique_jwks_uri(label: &str) -> String {
    format!("https://example.com/{label}-{}.json", Uuid::new_v4())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL-backed Redis integration test"]
fn jwks_redis_shared_runtime_state_allows_single_half_open_probe() -> TestResult {
    let Some(redis_url) = test_jwks_redis_url() else {
        return Ok(());
    };
    let uri = unique_jwks_uri("half-open-probe");
    clear_jwks_redis_keys(&redis_url, &uri)?;
    let state_a = redis_jwks_runtime_state(&redis_url)?;
    let state_b = redis_jwks_runtime_state(&redis_url)?;
    let policy = JwksRuntimePolicy {
        circuit_open_fails: 1,
        circuit_reset_secs: 1,
        ..JwksRuntimePolicy::default()
    };

    circuit_on_failure_with_state(&state_a, &policy, &uri);
    assert!(matches!(
        circuit_phase_with_state(&state_b, &uri),
        CircuitPhase::Open
    ));
    std::thread::sleep(std::time::Duration::from_millis(1_100));

    assert!(
        circuit_allow_fetch_with_state(&state_a, &policy, &uri),
        "first node should acquire the shared half-open JWKS probe"
    );
    assert!(
        !circuit_allow_fetch_with_state(&state_b, &policy, &uri),
        "second node must not race the shared half-open JWKS probe"
    );

    clear_jwks_redis_keys(&redis_url, &uri)?;
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL-backed Redis integration test"]
fn jwks_redis_shared_runtime_state_shares_kid_fingerprint_history() -> TestResult {
    let Some(redis_url) = test_jwks_redis_url() else {
        return Ok(());
    };
    let uri = unique_jwks_uri("kid-history");
    clear_jwks_redis_keys(&redis_url, &uri)?;
    let state_a = redis_jwks_runtime_state(&redis_url)?;
    let state_b = redis_jwks_runtime_state(&redis_url)?;
    let policy = JwksRuntimePolicy::default();
    let first = HashMap::from([("shared-kid".to_string(), "fingerprint-1".to_string())]);
    let second = HashMap::from([("shared-kid".to_string(), "fingerprint-2".to_string())]);

    let first_changed = test_context(
        shared_kid_reuse_changed_with_state(&state_a, &policy, &uri, &first),
        "first JWKS kid fingerprint write should succeed",
    )?;
    assert!(!first_changed);
    let second_changed = test_context(
        shared_kid_reuse_changed_with_state(&state_b, &policy, &uri, &second),
        "second JWKS kid fingerprint read should succeed",
    )?;
    assert!(
        second_changed,
        "kid reuse with changed material must be detected across JWKS runtime states"
    );

    clear_jwks_redis_keys(&redis_url, &uri)?;
    Ok(())
}

#[test]
fn jwks_redis_shared_runtime_state_unavailable_fails_closed() -> TestResult {
    let uri = unique_jwks_uri("redis-unavailable");
    let state = redis_jwks_runtime_state("redis://127.0.0.1:1/")?;
    let policy = JwksRuntimePolicy {
        circuit_open_fails: 1,
        ..JwksRuntimePolicy::default()
    };
    let kid_fps = HashMap::from([("shared-kid".to_string(), "fingerprint-1".to_string())]);

    assert!(
        !circuit_allow_fetch_with_state(&state, &policy, &uri),
        "unavailable shared JWKS circuit state must deny fetches"
    );
    assert!(matches!(
        circuit_phase_with_state(&state, &uri),
        CircuitPhase::Open
    ));
    assert!(
        shared_kid_reuse_changed_with_state(&state, &policy, &uri, &kid_fps).is_err(),
        "unavailable shared kid fingerprint state must be surfaced to callers"
    );
    Ok(())
}
