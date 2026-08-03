#[test]
fn test_jwt_bearer_grant_sets_audience_and_subject() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let resource = "https://api.example.com/resource".to_string();

    let access_token = match must_ok!(
        issuer.issue_jwt_bearer_token(
            "test_client",
            "jwt-subject-123",
            Some("read".to_string()),
            Some(resource.as_str()),
            None,
        ),
        "jwt-bearer token",
    ) {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };

    let meta = must_some!(
        get_bearer_meta(&issuer.token_store, &access_token)?,
        "bearer token metadata should be recorded"
    );
    assert_eq!(meta.user_id, "jwt-subject-123");
    assert_eq!(meta.audience, resource);
    Ok(())
}

#[test]
fn test_jwt_bearer_grant_rejects_openid_scope() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));

    match must_ok!(
        issuer.issue_jwt_bearer_token(
            "test_client",
            "jwt-subject-123",
            Some("openid".to_string()),
            None,
            None,
        ),
        "jwt-bearer token",
    ) {
        TokenResponse::Error { error, .. } => assert_eq!(error, "invalid_scope"),
        other => fail_test!("expected invalid_scope, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_access_tokens_are_unique_per_issue() -> TestResult {
    fn build_auth_req() -> AuthorizationRequest {
        AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            iss: None,
            redirect_uri: Some("https://example.com/callback".to_string()),
            resource: None,
            authorization_details: None,
            scope: Some("read write".to_string()),
            state: None,
            nonce: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
            code_challenge_method: Some("S256".to_string()),
            request_uri: None,
            request_object: None,
            request_object_claims: None,
            acr_values: None,
            max_age: None,
        }
    }

    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));

    let (code_1, _) = must_ok!(
        issuer.issue_authorization_code(build_auth_req(), "user123".to_string()),
        "authorization code #1",
    );
    let (code_2, _) = must_ok!(
        issuer.issue_authorization_code(build_auth_req(), "user123".to_string()),
        "authorization code #2",
    );

    let token_req_1 = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code_1),
        redirect_uri: Some("https://example.com/callback".to_string()),
        client_id: "test_client".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: None,
        request_object_claims: None,
    };
    let token_req_2 = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code_2),
        redirect_uri: Some("https://example.com/callback".to_string()),
        client_id: "test_client".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: None,
        request_object_claims: None,
    };

    let token_1 = match must_ok!(
        issuer.exchange_code_for_tokens(token_req_1, None),
        "token response #1",
    ) {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };
    let token_2 = match must_ok!(
        issuer.exchange_code_for_tokens(token_req_2, None),
        "token response #2",
    ) {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };

    assert_ne!(
        token_1, token_2,
        "access tokens must be unique per issuance to keep revocation and introspection semantics correct"
    );
    Ok(())
}
