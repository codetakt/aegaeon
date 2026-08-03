use super::*;

type TestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}", $context),
            Err(err) => err,
        }
    };
}

fn must_request(
    builder: http::request::Builder,
    proof: &str,
    uri: &str,
) -> Result<Request<()>, String> {
    builder
        .uri(uri)
        .header("DPoP", proof)
        .body(())
        .map_err(|err| format!("request construction should succeed for test fixtures: {err}"))
}

fn encode_json(value: &serde_json::Value) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|err| format!("test JSON fixtures should serialize: {err}"))
}

fn current_epoch_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| format!("wall clock should be after unix epoch in tests: {err}"))
}

#[test]
fn rejects_replays() {
    let mw = DpopMiddleware::new_process_local_for_tests();

    // First use of the JTI should succeed
    assert!(mw.check_and_store_jti("test-jti").is_ok());

    // Second use should be rejected as a replay
    assert_eq!(mw.check_and_store_jti("test-jti"), Err(DpopError::Replay));
}

#[test]
fn invalid_proof() -> TestResult {
    let mw = DpopMiddleware::new_process_local_for_tests();
    let req = must_ok!(
        must_request(
            Request::builder().method("GET"),
            "bad",
            "https://example.com/resource",
        ),
        "request construction",
    );
    assert_eq!(mw.verify(&req), Err(DpopError::InvalidProof));
    Ok(())
}

// --- Nonce store unit tests ---

#[test]
fn test_nonce_store_validate_current() -> TestResult {
    let store = DpopNonceStore::new_process_local(Duration::from_secs(300));
    let nonce = must_ok!(
        store.get_current_nonce(),
        "in-memory nonce store should issue nonce",
    );
    assert_eq!(store.validate_nonce(&nonce), Ok(true));
    assert_eq!(store.validate_nonce("bogus-nonce"), Ok(false));
    Ok(())
}

#[test]
fn test_nonce_store_rotation_grace() -> TestResult {
    let store = DpopNonceStore::new_process_local(Duration::from_secs(300));
    let (first, second) = must_ok!(
        store.force_rotate_for_test(),
        "test rotation should succeed"
    );
    assert_ne!(first, second, "nonce should have rotated");
    // Previous nonce is still valid during grace period.
    assert_eq!(
        store.validate_nonce(&first),
        Ok(true),
        "previous nonce should be accepted"
    );
    assert_eq!(
        store.validate_nonce(&second),
        Ok(true),
        "current nonce should be accepted"
    );
    Ok(())
}

#[test]
fn test_nonce_previous_rejected_after_grace_window() -> TestResult {
    // Grace window = TTL. After rotation, the previous nonce is accepted
    // for at most `ttl` duration. After that, it must be rejected.
    let store = DpopNonceStore::new_process_local(Duration::from_millis(50));
    let (first, second) = must_ok!(
        store.force_rotate_for_test(),
        "test rotation should succeed"
    );
    assert_ne!(first, second);
    // Immediately after rotation, first should still be in grace period.
    assert_eq!(
        store.validate_nonce(&first),
        Ok(true),
        "previous should be accepted within grace period"
    );
    must_ok!(
        store.backdate_rotation_for_test(Duration::from_millis(60)),
        "test rotation age should be updated",
    );
    assert_eq!(
        store.validate_nonce(&first),
        Ok(false),
        "previous should be rejected after grace period expires"
    );
    Ok(())
}

#[test]
fn test_nonce_store_expired_evicted() -> TestResult {
    let store = DpopNonceStore::new_process_local(Duration::from_secs(300));
    let (first, _) = must_ok!(
        store.force_rotate_for_test(),
        "first test rotation should succeed",
    );
    let _ = must_ok!(
        store.force_rotate_for_test(),
        "second test rotation should succeed",
    );
    assert_eq!(
        store.validate_nonce(&first),
        Ok(false),
        "evicted nonce should be rejected"
    );
    Ok(())
}

#[test]
fn nonce_store_poison_fails_closed_without_abort() -> TestResult {
    let store = DpopNonceStore::new_process_local(Duration::from_secs(300));
    must_ok!(
        store.poison_for_test(),
        "test store should use in-memory backend",
    );

    let err = must_err!(
        store.try_get_current_nonce(),
        "poisoned nonce store must fail closed",
    );
    assert!(matches!(err, DpopError::BackendUnavailable(message) if message.contains("poisoned")));
    Ok(())
}

#[test]
fn middleware_current_nonce_reports_backend_unavailable() -> TestResult {
    let store = Arc::new(DpopNonceStore::new_process_local(Duration::from_secs(300)));
    must_ok!(
        store.poison_for_test(),
        "test store should use in-memory backend",
    );

    let mw = DpopMiddleware::new_process_local_for_tests().with_nonce_store(Arc::clone(&store));
    let err = must_err!(
        mw.current_nonce(),
        "poisoned middleware nonce store must fail closed",
    );
    assert!(matches!(err, DpopError::BackendUnavailable(message) if message.contains("poisoned")));
    Ok(())
}

// --- Nonce integration with middleware ---

/// Build a minimal `DPoP` proof JWT (header.payload.signature) for testing.
/// The mock `verify_dpop` in `test_utils` validates claims but not crypto.
fn build_test_proof(method: &str, uri: &str, nonce: Option<&str>) -> Result<String, String> {
    build_test_proof_at(method, uri, current_epoch_secs()?, nonce)
}

fn build_test_proof_at(
    method: &str,
    uri: &str,
    iat: u64,
    nonce: Option<&str>,
) -> Result<String, String> {
    use serde_json::json;

    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }
    });
    let mut payload = json!({
        "htm": method,
        "htu": uri,
        "iat": iat,
        "jti": format!("test-jti-{}", rand::random::<u64>())
    });
    if let Some(n) = nonce {
        payload["nonce"] = json!(n);
    }

    let h = encode_json(&header)?;
    let p = encode_json(&payload)?;
    // Fake signature — mock verifier doesn't check it.
    let s = URL_SAFE_NO_PAD.encode(b"fakesig");
    Ok(format!("{h}.{p}.{s}"))
}

#[test]
fn configured_iat_window_rejects_stale_proof() -> TestResult {
    let mw = DpopMiddleware::new_process_local_for_tests().with_iat_window_secs(30);
    let now = current_epoch_secs()?;
    let proof = build_test_proof_at(
        "POST",
        "http://localhost/token",
        now.saturating_sub(45),
        None,
    )?;
    let req = must_ok!(
        must_request(Request::builder().method("POST"), &proof, "/token"),
        "request construction",
    );

    assert_eq!(mw.verify(&req), Err(DpopError::InvalidProof));
    Ok(())
}

#[test]
fn test_dpop_nonce_required_missing_nonce() -> TestResult {
    let store = Arc::new(DpopNonceStore::new_process_local(Duration::from_secs(300)));
    let mw = DpopMiddleware::new_process_local_for_tests().with_nonce_store(Arc::clone(&store));

    let proof = build_test_proof("POST", "http://localhost/token", None)?;
    let req = must_ok!(
        must_request(Request::builder().method("POST"), &proof, "/token"),
        "request construction",
    );
    let err = must_err!(mw.verify(&req), "missing DPoP nonce must fail closed");
    let DpopError::UseDpopNonce(nonce) = err else {
        fail_test!("expected nonce challenge");
    };
    assert!(!nonce.is_empty(), "should provide a fresh nonce");
    Ok(())
}

#[test]
fn test_dpop_nonce_roundtrip() -> TestResult {
    let store = Arc::new(DpopNonceStore::new_process_local(Duration::from_secs(300)));
    let mw = DpopMiddleware::new_process_local_for_tests().with_nonce_store(Arc::clone(&store));

    let nonce = must_ok!(
        store.get_current_nonce(),
        "in-memory nonce store should issue nonce",
    );
    let proof = build_test_proof("POST", "http://localhost/token", Some(&nonce))?;
    let req = must_ok!(
        must_request(Request::builder().method("POST"), &proof, "/token"),
        "request construction",
    );
    assert!(
        mw.verify(&req).is_ok(),
        "proof with valid nonce should succeed"
    );
    Ok(())
}

#[test]
fn test_dpop_nonce_invalid_value() -> TestResult {
    let store = Arc::new(DpopNonceStore::new_process_local(Duration::from_secs(300)));
    let mw = DpopMiddleware::new_process_local_for_tests().with_nonce_store(Arc::clone(&store));

    let proof = build_test_proof("POST", "http://localhost/token", Some("wrong-nonce"))?;
    let req = must_ok!(
        must_request(Request::builder().method("POST"), &proof, "/token"),
        "request construction",
    );
    let err = must_err!(mw.verify(&req), "invalid DPoP nonce must fail closed");
    assert!(matches!(err, DpopError::UseDpopNonce(_)));
    Ok(())
}

#[test]
fn test_dpop_nonce_not_required() -> TestResult {
    // Without a nonce store, proofs without nonce should succeed.
    let mw = DpopMiddleware::new_process_local_for_tests();
    let proof = build_test_proof("POST", "http://localhost/token", None)?;
    let req = must_ok!(
        must_request(Request::builder().method("POST"), &proof, "/token"),
        "request construction",
    );
    assert!(
        mw.verify(&req).is_ok(),
        "nonce not required — should succeed"
    );
    Ok(())
}

#[test]
fn dpop_replay_material_is_length_delimited() {
    assert_ne!(
        DpopMiddleware::replay_material("jkt\0jti", "suffix"),
        DpopMiddleware::replay_material("jkt", "jti\0suffix"),
    );
}

#[test]
fn dpop_replay_material_uses_jkt_and_jti_only() {
    assert_ne!(
        DpopMiddleware::replay_material("jti", "jkt-a"),
        DpopMiddleware::replay_material("jti", "jkt-b"),
    );
    assert_ne!(
        DpopMiddleware::replay_material("jti-a", "jkt"),
        DpopMiddleware::replay_material("jti-b", "jkt"),
    );
}

#[test]
fn test_dpop_nonce_rotation_grace_in_middleware() -> TestResult {
    let store = Arc::new(DpopNonceStore::new_process_local(Duration::from_secs(300)));
    let mw = DpopMiddleware::new_process_local_for_tests().with_nonce_store(Arc::clone(&store));

    let (old_nonce, _) = must_ok!(
        store.force_rotate_for_test(),
        "test rotation should succeed"
    );

    let proof = build_test_proof("POST", "http://localhost/token", Some(&old_nonce))?;
    let req = must_ok!(
        must_request(Request::builder().method("POST"), &proof, "/token"),
        "request construction",
    );
    assert!(
        mw.verify(&req).is_ok(),
        "previous nonce should be accepted during grace period"
    );
    Ok(())
}

#[test]
fn test_dpop_duplicate_nonce_claims_are_invalid() -> TestResult {
    let store = Arc::new(DpopNonceStore::new_process_local(Duration::from_secs(300)));
    let mw = DpopMiddleware::new_process_local_for_tests().with_nonce_store(Arc::clone(&store));

    let h = URL_SAFE_NO_PAD.encode(br#"{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}}"#);
    let p = URL_SAFE_NO_PAD.encode(br#"{"htm":"POST","htu":"http://localhost/token","iat":1,"jti":"dup","nonce":"abc","nonce":"evil"}"#);
    let s = URL_SAFE_NO_PAD.encode(b"fakesig");
    let proof = format!("{h}.{p}.{s}");
    let req = must_ok!(
        must_request(Request::builder().method("POST"), &proof, "/token"),
        "request construction",
    );

    assert_eq!(mw.verify(&req), Err(DpopError::InvalidProof));
    Ok(())
}
