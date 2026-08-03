
#[test]
fn generate_random_kid_unique() {
    let kid1 = generate_random_kid();
    let kid2 = generate_random_kid();
    assert_ne!(kid1, kid2, "random kids should be unique");
    assert!(!kid1.is_empty());
}

// ---------------------------------------------------------------
// API key tests (unit-level)
// ---------------------------------------------------------------

#[test]
fn sha256_array_produces_32_bytes_for_api_key() {
    let key = "aeg_test_api_key_value";
    let hash = sha256_array(key.as_bytes());
    assert_eq!(hash.len(), 32);

    // Same input should produce same hash
    let hash2 = sha256_array(key.as_bytes());
    assert_eq!(hash, hash2);
}

#[test]
fn sha256_array_different_inputs_produce_different_hashes() {
    let hash1 = sha256_array(b"aeg_key_1");
    let hash2 = sha256_array(b"aeg_key_2");
    assert_ne!(hash1, hash2);
}

#[test]
fn constant_time_eq_api_key_hash_comparison() {
    let key = "aeg_test_key_for_timing";
    let hash = sha256_array(key.as_bytes());
    let hash_copy = sha256_array(key.as_bytes());
    assert!(
        constant_time_eq(&hash, &hash_copy),
        "same hashes should match"
    );

    let other_hash = sha256_array(b"different_key");
    assert!(
        !constant_time_eq(&hash, &other_hash),
        "different hashes should not match"
    );
}

// ---------------------------------------------------------------
// P2: Audit helpers
// ---------------------------------------------------------------

#[test]
fn encode_decode_keyset_page_token_roundtrip() {
    let values = vec![
        "2026-07-04T01:02:03.123456Z".to_string(),
        "018f3b8f-0c27-7d93-aef1-5af7d75a2de1".to_string(),
    ];
    let token = encode_keyset_page_token(values.clone());
    assert_eq!(decode_keyset_page_token(&token, 2), Some(values));
}

#[test]
fn decode_keyset_page_token_rejects_garbage() {
    assert_eq!(decode_keyset_page_token("not-base64!!!", 2), None);
    assert_eq!(decode_keyset_page_token("", 2), None);
    assert_eq!(decode_keyset_page_token(&"a".repeat(4096), 2), None);
    assert_eq!(
        decode_keyset_page_token(&URL_SAFE_NO_PAD.encode(br#"{"v":1,"values":["only-one"]}"#), 2),
        None
    );
}

#[test]
fn pagination_params_default_limit_and_empty_cursor() -> ManagementTestResult {
    let pagination = must_ok!(
        pagination_params(
            &PaginationQuery {
                page_size: None,
                page_token: None,
            },
            2,
            "req-1",
        ),
        "valid pagination"
    );
    assert!(
        pagination.limit > 0 && pagination.limit <= 100,
        "default limit should be between 1 and 100"
    );
    assert_eq!(pagination.cursor_value(0), None);
    Ok(())
}

#[test]
fn pagination_params_respects_keyset_page_token() -> ManagementTestResult {
    let token = encode_keyset_page_token([
        "2026-07-04T01:02:03.123456Z".to_string(),
        "018f3b8f-0c27-7d93-aef1-5af7d75a2de1".to_string(),
    ]);
    let pagination = must_ok!(
        pagination_params(
            &PaginationQuery {
                page_size: None,
                page_token: Some(token),
            },
            2,
            "req-1",
        ),
        "valid pagination"
    );
    assert_eq!(
        pagination.cursor_value(0),
        Some("2026-07-04T01:02:03.123456Z")
    );
    assert_eq!(
        pagination.cursor_value(1),
        Some("018f3b8f-0c27-7d93-aef1-5af7d75a2de1")
    );
    Ok(())
}

// ---------------------------------------------------------------
// P2: UpdateClient validation — full field support
// ---------------------------------------------------------------

#[test]
fn update_client_request_redirect_uris_is_update() {
    let mut req = base_update_client_request();
    req.redirect_uris = Some(vec!["https://example.com/cb".to_string()]);
    let has_update = req.name.is_some()
        || req.redirect_uris.is_some()
        || req.allowed_grant_types.is_some()
        || req.allowed_scopes.is_some()
        || req.token_endpoint_authentication_method.is_some()
        || req.oauth_profile_id.is_some()
        || req.comment.is_some();
    assert!(has_update);
}

#[test]
fn validate_redirect_uris_multiple_valid_uris() -> TestResult {
    let uris = vec![
        "https://example.com/cb".to_string(),
        "https://app.example.com/auth".to_string(),
        "http://localhost:3000/cb".to_string(),
    ];
    let Ok(result) = validate_redirect_uris(&uris, "req-1") else {
        return Err(io::Error::other("expected valid redirect URIs").into());
    };
    assert_eq!(result.len(), 3);
    Ok(())
}

#[test]
fn validate_redirect_uris_empty_list() -> TestResult {
    let uris: Vec<String> = vec![];
    let Ok(result) = validate_redirect_uris(&uris, "req-1") else {
        return Err(io::Error::other("expected empty redirect URI list to validate").into());
    };
    assert_eq!(result.len(), 0);
    Ok(())
}

// ---------------------------------------------------------------
// P5: Audit read — RBAC helper
// ---------------------------------------------------------------

#[test]
fn role_allows_audit_read_for_owner() {
    assert!(role_allows_audit_read("OWNER"));
}

#[test]
fn role_allows_audit_read_for_administrator() {
    assert!(role_allows_audit_read("ADMINISTRATOR"));
}

#[test]
fn role_allows_audit_read_for_auditor() {
    assert!(role_allows_audit_read("AUDITOR"));
}

#[test]
fn role_denies_audit_read_for_operator() {
    assert!(!role_allows_audit_read("OPERATOR"));
}

#[test]
fn role_denies_audit_read_for_readonly() {
    assert!(!role_allows_audit_read("READONLY"));
}

#[test]
fn role_denies_audit_read_for_empty() {
    assert!(!role_allows_audit_read(""));
}

#[test]
fn role_denies_audit_read_for_lowercase() {
    assert!(!role_allows_audit_read("owner"));
    assert!(!role_allows_audit_read("auditor"));
}
