#[test]
fn test_authorization_details_propagation() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let details = json!([{"type": "payment", "actions": ["read"]}]);

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: Some(details.clone()),
        scope: Some("read".to_string()),
        state: Some("xyz".to_string()),
        nonce: Some("abc".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    };

    let (code, _) = must_ok!(
        issuer.issue_authorization_code(auth_req, "user123".to_string()),
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

    let response = must_ok!(
        issuer.exchange_code_for_tokens(token_req, None),
        "token exchange",
    );

    match response {
        TokenResponse::Success {
            authorization_details,
            ..
        } => {
            assert_eq!(authorization_details, Some(details));
        }
        other => fail_test!("expected success response, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_resource_indicator_sets_audience_on_code_exchange() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let resource = "https://api.example.com/resource".to_string();

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: Some(resource.clone()),
        authorization_details: None,
        scope: Some("read".to_string()),
        state: Some("xyz".to_string()),
        nonce: Some("abc".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    };

    let (code, _) = must_ok!(
        issuer.issue_authorization_code(auth_req, "user123".to_string()),
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

    let access_token = match must_ok!(
        issuer.exchange_code_for_tokens(token_req, None),
        "token exchange",
    ) {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };

    let meta = must_some!(
        get_bearer_meta(&issuer.token_store, &access_token)?,
        "bearer token metadata should be recorded"
    );
    assert_eq!(meta.audience, resource);
    Ok(())
}

#[test]
fn test_request_object_authorize_audience_does_not_block_code_exchange() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let (code, _) = must_ok!(
        issuer.issue_authorization_code(authorization_request("read", None), "user123".to_string()),
        "authorization code",
    );
    let mut token_req = token_request_for_code(code, None);
    token_req.request_object_claims = Some(aegaeon_jose::RequestObjectClaims {
        client_id: Some("test_client".to_string()),
        redirect_uri: Some("https://example.com/callback".to_string()),
        aud: Some(vec!["https://auth.example.com/authorize".to_string()]),
        ..Default::default()
    });

    match must_ok!(
        issuer.exchange_code_for_tokens(token_req, None),
        "token exchange",
    ) {
        TokenResponse::Success { .. } => {}
        other => fail_test!("expected success response, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_request_object_redirect_uri_mismatch_rejected_for_code_exchange() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let (code, _) = must_ok!(
        issuer.issue_authorization_code(authorization_request("read", None), "user123".to_string()),
        "authorization code",
    );
    let mut token_req = token_request_for_code(code, None);
    token_req.request_object_claims = Some(aegaeon_jose::RequestObjectClaims {
        client_id: Some("test_client".to_string()),
        redirect_uri: Some("https://attacker.example/callback".to_string()),
        aud: Some(vec!["https://auth.example.com/authorize".to_string()]),
        ..Default::default()
    });

    match must_ok!(
        issuer.exchange_code_for_tokens(token_req, None),
        "token exchange",
    ) {
        TokenResponse::Error {
            error,
            error_description,
        } => {
            assert_eq!(error, "invalid_grant");
            assert_eq!(
                error_description.as_deref(),
                Some("Request Object redirect_uri mismatch")
            );
        }
        other => fail_test!("expected invalid_grant, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_resource_indicator_mismatch_rejected_for_code_exchange() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let granted_resource = "https://api.example.com/resource".to_string();

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: Some(granted_resource),
        authorization_details: None,
        scope: Some("read".to_string()),
        state: Some("xyz".to_string()),
        nonce: Some("abc".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    };

    let (code, _) = must_ok!(
        issuer.issue_authorization_code(auth_req, "user123".to_string()),
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
        resource: Some("https://other.example.com/resource".to_string()),
        request_object_claims: None,
    };

    match must_ok!(
        issuer.exchange_code_for_tokens(token_req, None),
        "token exchange",
    ) {
        TokenResponse::Error { error, .. } => assert_eq!(error, "invalid_target"),
        other => fail_test!("expected invalid_target, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_resource_indicator_invalid_target_rejected_for_code_exchange() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("read".to_string()),
        state: Some("xyz".to_string()),
        nonce: Some("abc".to_string()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string()),
        code_challenge_method: Some("S256".to_string()),
        request_uri: None,
        request_object: None,
        request_object_claims: None,
        acr_values: None,
        max_age: None,
    };

    let (code, _) = must_ok!(
        issuer.issue_authorization_code(auth_req, "user123".to_string()),
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
        resource: Some("/relative".to_string()),
        request_object_claims: None,
    };

    match must_ok!(
        issuer.exchange_code_for_tokens(token_req, None),
        "token exchange",
    ) {
        TokenResponse::Error { error, .. } => assert_eq!(error, "invalid_target"),
        other => fail_test!("expected invalid_target, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_resource_indicator_sets_audience_on_client_credentials() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let resource = "https://api.example.com/resource".to_string();

    let access_token = match must_ok!(
        issuer.issue_client_credentials_token(
            "test_client",
            Some("read".to_string()),
            Some(resource.as_str()),
            None,
        ),
        "client credentials token",
    ) {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };

    let meta = must_some!(
        get_bearer_meta(&issuer.token_store, &access_token)?,
        "bearer token metadata should be recorded"
    );
    assert_eq!(meta.audience, resource);
    Ok(())
}
