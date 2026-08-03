
// ---------------------------------------------------------------
// P0: CSRF token generation
// ---------------------------------------------------------------

#[test]
fn csrf_token_is_nonempty_and_unique() -> TestResult {
    let t1 = must_ok!(generate_csrf_token(), "csrf token");
    let t2 = must_ok!(generate_csrf_token(), "csrf token");
    assert!(!t1.is_empty());
    assert!(!t2.is_empty());
    assert_ne!(t1, t2);
    Ok(())
}

// ---------------------------------------------------------------
// Existing tests below
// ---------------------------------------------------------------

fn base_update_client_request() -> UpdateClientRequest {
    UpdateClientRequest {
        base_configuration_version_id: "00000000-0000-0000-0000-000000000000".to_string(),
        oauth_profile_id: None,
        name: None,
        redirect_uris: None,
        allowed_grant_types: None,
        allowed_scopes: None,
        token_endpoint_authentication_method: None,
        comment: None,
    }
}

#[test]
fn update_client_request_no_fields_is_not_update() {
    let req = base_update_client_request();
    // All fields None → has_update should be false
    let has_update = req.name.is_some()
        || req.redirect_uris.is_some()
        || req.allowed_grant_types.is_some()
        || req.allowed_scopes.is_some()
        || req.token_endpoint_authentication_method.is_some()
        || req.oauth_profile_id.is_some()
        || req.comment.is_some();
    assert!(!has_update);
}

#[test]
fn update_client_request_name_is_update() {
    let mut req = base_update_client_request();
    req.name = Some("new-name".to_string());
    let has_update =
        req.name.is_some() || req.redirect_uris.is_some() || req.oauth_profile_id.is_some();
    assert!(has_update);
}

#[test]
fn update_client_request_oauth_profile_clear_is_update() {
    let mut req = base_update_client_request();
    req.oauth_profile_id = Some(None);
    let has_update = req.oauth_profile_id.is_some();
    assert!(has_update);
}

#[test]
fn validate_redirect_uris_accepts_https() -> TestResult {
    let uris = vec!["https://example.com/callback".to_string()];
    let Ok(result) = validate_redirect_uris(&uris, "req-1") else {
        return Err(io::Error::other("expected https redirect URI to be valid").into());
    };
    assert_eq!(result, vec!["https://example.com/callback"]);
    Ok(())
}

#[test]
fn validate_redirect_uris_accepts_http_localhost() {
    let uris = vec!["http://localhost:8080/callback".to_string()];
    let result = validate_redirect_uris(&uris, "req-1");
    assert!(result.is_ok());
}

#[test]
fn validate_redirect_uris_accepts_http_ipv6_loopback() {
    let uris = vec!["http://[::1]:8080/callback".to_string()];
    let result = validate_redirect_uris(&uris, "req-1");
    assert!(result.is_ok());
}

#[test]
fn validate_redirect_uris_rejects_http_non_loopback() {
    let uris = vec!["http://example.com/callback".to_string()];
    let result = validate_redirect_uris(&uris, "req-1");
    assert!(result.is_err());
}

#[test]
fn validate_redirect_uris_rejects_fragment() {
    let uris = vec!["https://example.com/callback#frag".to_string()];
    let result = validate_redirect_uris(&uris, "req-1");
    assert!(result.is_err());
}

#[test]
fn validate_redirect_uris_rejects_userinfo() {
    let uris = vec!["https://user@example.com/callback".to_string()];
    let result = validate_redirect_uris(&uris, "req-1");
    assert!(result.is_err());
}

#[tokio::test]
async fn validate_redirect_uris_error_details_do_not_echo_input_uri() -> TestResult {
    let sensitive_uri = "https://user:secret@example.com/callback?token=hidden";
    let uris = vec![sensitive_uri.to_string()];
    let response = must_err!(
        validate_redirect_uris(&uris, "req-1"),
        "secret-bearing redirect URI must be rejected",
    );
    let body = management_error_response_body(response).await?;
    assert_eq!(
        body.details.as_ref(),
        Some(&serde_json::json!({ "field": "redirectUri" }))
    );
    let serialized = serde_json::to_string(&body)?;
    assert!(!serialized.contains(sensitive_uri));
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("hidden"));
    Ok(())
}

#[test]
fn page_token_round_trip() {
    let values = vec![
        "2026-07-04T01:02:03.123456Z".to_string(),
        "018f3b8f-0c27-7d93-aef1-5af7d75a2de1".to_string(),
    ];
    let token = encode_keyset_page_token(values.clone());
    assert_eq!(decode_keyset_page_token(&token, 2), Some(values));
    assert_eq!(decode_keyset_page_token("not-a-token", 2), None);
}

#[test]
fn normalize_optional_text_clears_empty() {
    assert_eq!(normalize_optional_text(None), None);
    assert_eq!(normalize_optional_text(Some("")), None);
    assert_eq!(normalize_optional_text(Some("  ")), None);
    assert_eq!(
        normalize_optional_text(Some(" value ")),
        Some("value".to_string())
    );
}
