#[test]
fn test_token_exchange_rejects_wrong_client_without_consuming_code() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "legit_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("read profile".to_string()),
        state: Some("state-123".to_string()),
        nonce: Some("nonce-456".to_string()),
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

    // Attacker attempts redemption with a different client identifier.
    let attacker_attempt = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code.clone()),
        redirect_uri: Some("https://example.com/callback".to_string()),
        client_id: "attacker_client".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: None,
        request_object_claims: None,
    };

    match must_ok!(
        issuer.exchange_code_for_tokens(attacker_attempt, None),
        "token exchange result",
    ) {
        TokenResponse::Error { error, .. } => assert_eq!(error, "invalid_client"),
        other => fail_test!("expected invalid_client error for mismatched client_id, got {other:?}"),
    }

    // Legitimate client can still redeem after the failed attacker attempt.
    let legitimate_attempt = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code),
        redirect_uri: Some("https://example.com/callback".to_string()),
        client_id: "legit_client".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: None,
        request_object_claims: None,
    };

    match must_ok!(
        issuer.exchange_code_for_tokens(legitimate_attempt, None),
        "legitimate token exchange",
    ) {
        TokenResponse::Success { .. } => {}
        other => fail_test!("expected success after attacker failure, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_token_exchange_rejects_authorization_code_policy_without_consuming_code() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "legit_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("read profile".to_string()),
        state: Some("state-policy".to_string()),
        nonce: Some("nonce-policy".to_string()),
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
        code: Some(code.clone()),
        redirect_uri: Some("https://example.com/callback".to_string()),
        client_id: "legit_client".to_string(),
        client_secret: Some("secret".to_string()),
        refresh_token: None,
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string()),
        resource: None,
        request_object_claims: None,
    };

    match must_ok!(
        issuer.exchange_code_for_tokens_bound_with_grant_policy(
            token_req.clone(),
            None,
            None,
            false,
            true,
        ),
        "policy-rejected token exchange",
    ) {
        TokenResponse::Error { error, .. } => assert_eq!(error, "unauthorized_client"),
        other => fail_test!("expected unauthorized_client policy error, got {other:?}"),
    }

    match must_ok!(
        issuer.exchange_code_for_tokens_bound_with_grant_policy(token_req, None, None, true, true),
        "policy-restored token exchange",
    ) {
        TokenResponse::Success { .. } => {}
        other => fail_test!("expected success after policy rejection, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_token_exchange_rejects_oidc_session_failure_without_consuming_code() -> TestResult {
    let code_store = AuthCodeStore::new_process_local_for_tests();
    let token_store = TokenStore::new_process_local_for_tests();
    let failing_sessions = crate::oidc::OidcSessionStore::new_redis_for_test(
        "redis://127.0.0.1:1/",
        "oidc-session-failure",
        10,
    )?;
    let failing_issuer = TokenIssuer::with_stores(
        Arc::new(InMemoryKeyManager::new()),
        code_store.clone(),
        token_store.clone(),
    )
    .with_oidc(Some(enabled_oidc_config()?))
    .with_oidc_sessions(Some(failing_sessions));

    let auth_req = AuthorizationRequest {
        scope: Some("openid profile".to_string()),
        state: Some("state-oidc-session-failure".to_string()),
        nonce: Some("nonce-oidc-session-failure".to_string()),
        ..authorization_request("openid profile", None)
    };
    let (code, _) = must_ok!(
        failing_issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some("auth-session-oidc-session-failure".to_string()),
            ..AuthorizationCodeIssueInput::new(auth_req, "user123".to_string(), true, 0)
        }),
        "authorization code",
    );
    let token_req = TokenRequest {
        client_id: "test_client".to_string(),
        code: Some(code.clone()),
        ..token_request_for_code(code.clone(), None)
    };

    match must_ok!(
        failing_issuer.exchange_code_for_tokens(token_req.clone(), None),
        "OIDC session failure token exchange",
    ) {
        TokenResponse::Error { error, .. } => assert_eq!(error, "server_error"),
        other => fail_test!("expected server_error for OIDC session failure, got {other:?}"),
    }

    let successful_issuer = TokenIssuer::with_stores(
        Arc::new(InMemoryKeyManager::new()),
        code_store,
        token_store,
    )
    .with_oidc(Some(enabled_oidc_config()?));
    match must_ok!(
        successful_issuer.exchange_code_for_tokens(token_req.clone(), None),
        "token exchange after OIDC session failure",
    ) {
        TokenResponse::Success { id_token, .. } => {
            assert!(id_token.is_some(), "expected id_token after retry");
        }
        other => fail_test!("expected success after OIDC session failure, got {other:?}"),
    }

    let reuse_error = must_err!(
        successful_issuer.exchange_code_for_tokens(token_req, None),
        "authorization code reuse after successful exchange",
    );
    assert!(
        reuse_error.contains("Invalid or expired code"),
        "expected invalid or expired code after successful consume, got {reuse_error:?}",
    );
    Ok(())
}
