#[test]
fn test_pkce_verification() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert!(verify_pkce(verifier, challenge));
}

#[test]
fn test_token_issuance_flow() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));

    // Step 1: Authorization request
    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("read write".to_string()),
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

    // Step 2: Token exchange
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
            access_token,
            token_type,
            ..
        } => {
            assert_eq!(token_type, "Bearer");
            assert!(!access_token.is_empty());
        }
        other => fail_test!("expected success response, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_authorization_code_requires_pkce_challenge_and_method() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));

    for (challenge, method, expected) in [
        (None, None, "PKCE required"),
        (
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            None,
            "PKCE required",
        ),
        (None, Some("S256"), "PKCE required"),
        (
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            Some("plain"),
            "PKCE required (S256)",
        ),
    ] {
        let auth_req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            iss: None,
            redirect_uri: Some("https://example.com/callback".to_string()),
            resource: None,
            authorization_details: None,
            scope: Some("read write".to_string()),
            state: Some(format!("state-{method:?}-{challenge:?}")),
            nonce: Some(format!("nonce-{method:?}-{challenge:?}")),
            code_challenge: challenge.map(str::to_string),
            code_challenge_method: method.map(str::to_string),
            request_uri: None,
            request_object: None,
            request_object_claims: None,
            acr_values: None,
            max_age: None,
        };

        let err = must_err!(
            issuer.issue_authorization_code(auth_req, "user123".to_string()),
            "authorization code issue should reject missing or unsupported PKCE",
        );
        assert_eq!(err, expected);
    }
    Ok(())
}

#[test]
fn test_refresh_invalid_resource_does_not_consume_refresh_token() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let refresh_token = issue_refresh_token_for_resource(&issuer, Some("https://api.example/a"))?;

    match must_ok!(
        issuer.refresh_access_token(&refresh_token, Some("https://api.example/b"), None),
        "refresh with invalid resource",
    ) {
        TokenResponse::Error { error, .. } => assert_eq!(error, "invalid_target"),
        other => fail_test!("expected invalid_target response, got {other:?}"),
    }

    assert!(!is_refresh_revoked(&issuer.token_store, &refresh_token)?);
    match must_ok!(
        issuer.refresh_access_token(&refresh_token, None, None),
        "refresh after invalid_target",
    ) {
        TokenResponse::Success {
            refresh_token: Some(new_refresh_token),
            ..
        } => assert_ne!(new_refresh_token, refresh_token),
        other => fail_test!("expected successful refresh after invalid_target, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn test_prepared_refresh_invalid_resource_does_not_consume_refresh_token() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let refresh_token = issue_refresh_token_for_resource(&issuer, Some("https://api.example/a"))?;
    let prepared_refresh = must_ok!(
        issuer.token_store.prepare_refresh_rotation(&refresh_token),
        "prepare refresh grant",
    );

    match must_ok!(
        issuer
            .refresh_prepared_access_token_bound_async(
                refresh_token.clone(),
                prepared_refresh,
                Some("https://api.example/b".to_string()),
                None,
                None,
            )
            .await,
        "prepared refresh with invalid resource",
    ) {
        TokenResponse::Error { error, .. } => assert_eq!(error, "invalid_target"),
        other => fail_test!("expected invalid_target response, got {other:?}"),
    }

    assert!(!is_refresh_revoked(&issuer.token_store, &refresh_token)?);
    match must_ok!(
        issuer.refresh_access_token(&refresh_token, None, None),
        "refresh after prepared invalid_target",
    ) {
        TokenResponse::Success {
            refresh_token: Some(new_refresh_token),
            ..
        } => assert_ne!(new_refresh_token, refresh_token),
        other => fail_test!("expected successful refresh after invalid_target, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn test_prepared_refresh_rejects_mismatched_previous_token() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let refresh_token = issue_refresh_token_for_resource(&issuer, None)?;
    let prepared_refresh = must_ok!(
        issuer.token_store.prepare_refresh_rotation(&refresh_token),
        "prepare refresh grant",
    );

    match must_ok!(
        issuer
            .refresh_prepared_access_token_bound_async(
                "different-refresh-token".to_string(),
                prepared_refresh,
                None,
                None,
                None,
            )
            .await,
        "prepared refresh with mismatched previous token",
    ) {
        TokenResponse::Error {
            error,
            error_description,
        } => {
            assert_eq!(error, "server_error");
            assert_eq!(
                error_description.as_deref(),
                Some("prepared refresh token mismatch")
            );
        }
        other => fail_test!("expected server_error response, got {other:?}"),
    }

    match must_ok!(
        issuer.refresh_access_token(&refresh_token, None, None),
        "refresh after prepared token mismatch",
    ) {
        TokenResponse::Success {
            refresh_token: Some(new_refresh_token),
            ..
        } => assert_ne!(new_refresh_token, refresh_token),
        other => fail_test!("expected successful refresh after token mismatch, got {other:?}"),
    }
    Ok(())
}

#[test]
fn test_refresh_reuse_revokes_successor_family() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let refresh_token = issue_refresh_token_for_resource(&issuer, None)?;

    let (successor_refresh_token, successor_access_token) = match must_ok!(
        issuer.refresh_access_token(&refresh_token, None, None),
        "first refresh",
    ) {
        TokenResponse::Success {
            access_token,
            refresh_token: Some(refresh_token),
            ..
        } => (refresh_token, access_token),
        other => fail_test!("expected first refresh success, got {other:?}"),
    };

    let err = must_err!(
        issuer.refresh_access_token(&refresh_token, None, None),
        "refresh token reuse should fail",
    );
    assert_eq!(err, "Invalid or rotated refresh token");

    assert!(verify_access_token(&issuer.token_store, &successor_access_token)?.is_none());
    assert!(is_refresh_revoked(
        &issuer.token_store,
        &successor_refresh_token
    )?);
    let err = must_err!(
        issuer.refresh_access_token(&successor_refresh_token, None, None),
        "successor should be revoked after parent reuse",
    );
    assert_eq!(err, "Invalid or rotated refresh token");
    Ok(())
}
