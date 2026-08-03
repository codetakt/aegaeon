fn issue_refresh_token_for_resource(
    issuer: &TokenIssuer,
    resource: Option<&str>,
) -> Result<String, String> {
    let (code, _) = must_ok!(
        issuer.issue_authorization_code(
            authorization_request("read offline_access", resource),
            "user123".to_string(),
        ),
        "authorization code",
    );
    match must_ok!(
        issuer.exchange_code_for_tokens(token_request_for_code(code, resource), None),
        "token exchange",
    ) {
        TokenResponse::Success {
            refresh_token: Some(refresh_token),
            ..
        } => Ok(refresh_token),
        other => fail_test!("expected refresh token in success response, got {other:?}"),
    }
}

fn issue_oidc_id_token_payload_for_auth_session(
    issuer: &TokenIssuer,
    state: &str,
    nonce: &str,
    auth_session_id: &str,
) -> Result<Value, String> {
    let auth_req = AuthorizationRequest {
        scope: Some("openid profile".to_string()),
        state: Some(state.to_string()),
        nonce: Some(nonce.to_string()),
        ..authorization_request("openid profile", None)
    };
    let (code, _) = must_ok!(
        issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
            auth_session_id: Some(auth_session_id.to_string()),
            ..AuthorizationCodeIssueInput::new(
                auth_req,
                "user123".to_string(),
                true,
                1_700_000_000,
            )
        }),
        "authorization code",
    );

    let id_token = match must_ok!(
        issuer.exchange_code_for_tokens(token_request_for_code(code, None), None),
        "token exchange",
    ) {
        TokenResponse::Success {
            id_token: Some(id_token),
            ..
        } => id_token,
        other => fail_test!("expected id_token in success response, got {other:?}"),
    };

    decode_jwt_part(must_some!(id_token.split('.').nth(1), "jwt payload"))
}

#[test]
fn test_id_token_sid_is_scoped_to_auth_session() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
        .with_oidc(Some(enabled_oidc_config()?))
        .with_oidc_sessions(Some(
            crate::oidc::OidcSessionStore::new_process_local_with_ttl_for_tests(600),
        ));

    let payload_a = issue_oidc_id_token_payload_for_auth_session(
        &issuer,
        "state-auth-session-a",
        "nonce-auth-session-a",
        "auth-session-a",
    )?;
    let payload_b = issue_oidc_id_token_payload_for_auth_session(
        &issuer,
        "state-auth-session-b",
        "nonce-auth-session-b",
        "auth-session-b",
    )?;

    let sid_a = must_some!(
        payload_a.get("sid").and_then(Value::as_str),
        "first id_token sid"
    );
    let sid_b = must_some!(
        payload_b.get("sid").and_then(Value::as_str),
        "second id_token sid"
    );
    assert_ne!(sid_a, sid_b);
    Ok(())
}

#[test]
fn test_id_token_filters_broker_managed_custom_claims_by_release_policy() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
        .with_oidc(Some(enabled_oidc_config()?));

    let mut local_profile = OidcProfileClaims {
        display_name: Some("User".to_string()),
        updated_at_epoch_seconds: Some(1_700_000_000),
        ..Default::default()
    };
    local_profile
        .custom_claims
        .insert("roles".to_string(), json!(["admins"]));
    local_profile
        .custom_claims
        .insert("organization".to_string(), json!("Platform"));
    local_profile
        .custom_claims
        .insert("department".to_string(), json!("Identity"));

    let claim_release_policy = UpstreamClaimReleasePolicy {
        managed_custom_claims: vec!["organization".to_string(), "roles".to_string()],
        id_token_custom_claims: vec!["organization".to_string()],
        userinfo_custom_claims: vec!["roles".to_string()],
    };

    let auth_req = AuthorizationRequest {
        response_type: "code".to_string(),
        client_id: "test_client".to_string(),
        iss: None,
        redirect_uri: Some("https://example.com/callback".to_string()),
        resource: None,
        authorization_details: None,
        scope: Some("openid profile".to_string()),
        state: Some("state-123".to_string()),
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
            auth_session_id: Some("auth-session-custom-claims".to_string()),
            local_profile: Some(local_profile),
            claim_release_policy: Some(claim_release_policy),
            ..AuthorizationCodeIssueInput::new(
                auth_req,
                "user123".to_string(),
                true,
                1_700_000_000,
            )
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

    let id_token = match must_ok!(
        issuer.exchange_code_for_tokens(token_req, None),
        "token exchange",
    ) {
        TokenResponse::Success {
            id_token: Some(id_token),
            ..
        } => id_token,
        other => fail_test!("expected id_token in success response, got {other:?}"),
    };

    let payload = decode_jwt_part(must_some!(id_token.split('.').nth(1), "jwt payload"))?;
    assert_eq!(
        payload.get("organization").and_then(|value| value.as_str()),
        Some("Platform")
    );
    assert_eq!(
        payload.get("department").and_then(|value| value.as_str()),
        Some("Identity")
    );
    assert!(payload.get("roles").is_none());
    Ok(())
}
