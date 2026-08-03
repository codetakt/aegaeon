
// ---------------------------------------------------------------
// P0: enforce_management_csrf unit tests
// ---------------------------------------------------------------

#[test]
fn csrf_rejects_missing_origin() {
    let mgmt = test_management_state();
    let headers = HeaderMap::new();
    let result = enforce_management_csrf(&headers, "token123", &mgmt, "req-1");
    assert!(result.is_err());
}

#[test]
fn csrf_rejects_unconfigured_origins() -> TestResult {
    let cfg = ManagementConfig {
        allowed_origins: vec![],
        issuer_base_domain: "example.com".to_string(),
        cookie_secure: false,
        session_ttl_secs: 60,
        max_sessions: DEFAULT_MAX_SESSIONS,
        bootstrap_token_sha256: None,
    };
    let mgmt = ManagementState {
        cfg: Arc::new(cfg),
        sessions: Arc::new(ManagementSessionStore::new_process_local_for_tests()),
        login_rate_limiter: Arc::new(VerificationRateLimiter::new_process_local_for_tests()),
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, "https://evil.com".parse()?);
    headers.insert("x-csrf-token", "token123".parse()?);

    let result = enforce_management_csrf(&headers, "token123", &mgmt, "req-1");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn csrf_rejects_wrong_origin() -> TestResult {
    let mgmt = test_management_state();
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, "https://evil.com".parse()?);
    headers.insert("x-csrf-token", "token123".parse()?);

    let result = enforce_management_csrf(&headers, "token123", &mgmt, "req-1");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn csrf_rejects_missing_token_header() -> TestResult {
    let mgmt = test_management_state();
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, "https://admin.example.com".parse()?);

    let result = enforce_management_csrf(&headers, "token123", &mgmt, "req-1");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn csrf_rejects_duplicate_origin_header() -> TestResult {
    let mgmt = test_management_state();
    let mut headers = HeaderMap::new();
    headers.append(header::ORIGIN, "https://admin.example.com".parse()?);
    headers.append(header::ORIGIN, "https://admin.example.com".parse()?);
    headers.insert("x-csrf-token", "token123".parse()?);

    let result = enforce_management_csrf(&headers, "token123", &mgmt, "req-1");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn csrf_rejects_duplicate_token_header() -> TestResult {
    let mgmt = test_management_state();
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, "https://admin.example.com".parse()?);
    headers.append("x-csrf-token", "token123".parse()?);
    headers.append("x-csrf-token", "token123".parse()?);

    let result = enforce_management_csrf(&headers, "token123", &mgmt, "req-1");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn csrf_rejects_mismatched_token() -> TestResult {
    let mgmt = test_management_state();
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, "https://admin.example.com".parse()?);
    headers.insert("x-csrf-token", "wrong-token".parse()?);

    let result = enforce_management_csrf(&headers, "correct-token", &mgmt, "req-1");
    assert!(result.is_err());
    Ok(())
}

#[test]
fn csrf_accepts_valid_request() -> TestResult {
    let mgmt = test_management_state();
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, "https://admin.example.com".parse()?);
    headers.insert("x-csrf-token", "my-csrf-token".parse()?);

    let result = enforce_management_csrf(&headers, "my-csrf-token", &mgmt, "req-1");
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn management_json_admission_rejects_duplicate_keys_recursively() {
    assert!(validate_management_json_without_duplicate_keys(
        br#"{"email":"owner@example.com","email":"other@example.com"}"#
    )
    .is_err());
    assert!(validate_management_json_without_duplicate_keys(
        br#"{"configurationDocument":{"policy":{},"policy":{}}}"#
    )
    .is_err());
    assert!(validate_management_json_without_duplicate_keys(
        br#"{"configurationDocument":{"policy":{},"scopeAllowlist":["openid"]}}"#
    )
    .is_ok());
}
