#[test]
fn test_access_tokens_default_to_opaque() -> TestResult {
    let issuer = TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()));
    let response = must_ok!(
        issuer.issue_client_credentials_token("client", Some("read".to_string()), None, None),
        "client credentials token",
    );

    let access_token = match response {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };

    assert!(
        !access_token.contains('.'),
        "opaque access tokens must not be JWT-like by default"
    );
    Ok(())
}

#[test]
fn test_jwt_access_token_claims_when_enabled() -> TestResult {
    let issuer = "https://auth.example.com";
    let token_issuer = TokenIssuer::new_process_local_for_tests(public_jwt_key_manager()?)
        .with_issuer(issuer.to_string())
        .with_jwt_access_tokens_enabled(true);

    let response = must_ok!(
        token_issuer.issue_client_credentials_token("client", Some("read".to_string()), None, None),
        "client credentials token",
    );

    let access_token = match response {
        TokenResponse::Success { access_token, .. } => access_token,
        other => fail_test!("expected success response, got {other:?}"),
    };

    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3, "jwt access token must be JWS compact");

    let header = decode_jwt_part(parts[0])?;
    assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some("at+jwt"));

    let payload = decode_jwt_part(parts[1])?;
    assert_eq!(payload.get("iss").and_then(|v| v.as_str()), Some(issuer));
    assert_eq!(payload.get("sub").and_then(|v| v.as_str()), Some("client"));
    assert_eq!(
        payload.get("client_id").and_then(|v| v.as_str()),
        Some("client")
    );
    assert_eq!(payload.get("aud").and_then(|v| v.as_str()), Some("client"));
    assert!(payload.get("iat").and_then(Value::as_u64).is_some());
    assert!(payload.get("exp").and_then(Value::as_u64).is_some());
    assert!(payload.get("jti").and_then(|v| v.as_str()).is_some());
    Ok(())
}

#[test]
fn test_jwt_access_token_issuance_requires_public_verification_material() -> TestResult {
    let token_issuer =
        TokenIssuer::new_process_local_for_tests(Arc::new(InMemoryKeyManager::new()))
            .with_issuer("https://auth.example.com".to_string())
            .with_jwt_access_tokens_enabled(true);

    let response = must_ok!(
        token_issuer.issue_client_credentials_token("client", Some("read".to_string()), None, None),
        "client credentials token",
    );

    let TokenResponse::Error {
        error,
        error_description,
    } = response
    else {
        fail_test!("expected fail-closed JWT access token response");
    };
    assert_eq!(error, "server_error");
    assert_eq!(
        error_description.as_deref(),
        Some("JWT access token signing requires public verification material")
    );
    Ok(())
}
