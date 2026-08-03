#[test]
fn test_oidc_id_token_emission() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
        .with_oidc(Some(enabled_oidc_config()?));

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("openid profile".to_string()),
        state: Some("xyz".to_string()),
        nonce: Some("nonce-123".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    };

    let (code, _) = must_ok!(
        issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some("auth-session-id-token-emission".to_string()),
            ..AuthorizationCodeIssueInput::new(auth_req, "user123".to_string(), true, 0)
        }),
        "authorization code",
    );

    let token_req = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code),
        redirect_uri: Some("https://example.com/callback".to_string()),
        client_id: "test_client".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: None,
        request_object_claims: None,
    };

    match must_ok!(
        issuer.exchange_code_for_tokens(token_req, None),
        "token response",
    ) {
        TokenResponse::Success { id_token, .. } => {
            assert!(id_token.is_some(), "expected id_token for openid scope");
        }
        other => fail_test!("expected success response, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_openid_scope_rejected_without_oidc() {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("openid profile".to_string()),
        state: Some("xyz".to_string()),
        nonce: Some("nonce-123".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    };

    let result = issuer.issue_authorization_code(auth_req, "user123".to_string());
    assert!(result.is_err());
}

#[test]
fn test_openid_scope_rejected_without_auth_session_context() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
        .with_oidc(Some(enabled_oidc_config()?));
    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("openid profile".to_string()),
        state: Some("xyz".to_string()),
        nonce: Some("nonce-123".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    };

    let err = must_err!(
        issuer.issue_authorization_code(auth_req, "user123".to_string()),
        "authorization code without auth-session context",
    );
    assert_eq!(
        err,
        "auth session context is required when requesting the openid scope"
    );
    Ok(())
}
