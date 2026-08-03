#[test]
fn test_jwt_access_token_validator_rejects_unknown_header_backend_override() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::JwtAccessTokenHeader,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, "future");

    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();

    let token = sign_raw_jwt_parts(
        &format!(
            r#"{{"alg":"HS256","typ":"at+jwt","kid":"{}"}}"#,
            key_manager.key_id()
        ),
        r#"{
            "iss":"https://auth.example.com",
            "sub":"client",
            "aud":"client",
            "client_id":"client",
            "iat":unix_epoch_now_secs(),
            "exp":unix_epoch_now_secs().saturating_add(300),
            "jti":"test-jti"
        }"#,
        key_manager.as_ref(),
    )?;
    store_jwt_access_token(&token_store, &token)?;

    let validator =
        TokenValidator::with_policy(token_store, key_manager, SecurityPolicy::default())
            .with_jwt_access_tokens_enabled(true)
            .with_issuer(Some(issuer.to_string()));

    let err = must_err!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "unknown header backend override must fail closed",
    );

    if let Some(prev) = previous {
        std::env::set_var(key, prev);
    } else {
        std::env::remove_var(key);
    }

    assert_eq!(
        err,
        "access token parser backend misconfigured: unsupported raw JSON backend for jwt-access-token-header"
    );
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_unknown_payload_backend_override() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::JwtAccessTokenPayload,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, "future");

    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();

    let token = sign_raw_jwt_parts(
        &format!(
            r#"{{"alg":"HS256","typ":"at+jwt","kid":"{}"}}"#,
            key_manager.key_id()
        ),
        r#"{
            "iss":"https://auth.example.com",
            "sub":"client",
            "aud":"client",
            "client_id":"client",
            "iat":unix_epoch_now_secs(),
            "exp":unix_epoch_now_secs().saturating_add(300),
            "jti":"test-jti"
        }"#,
        key_manager.as_ref(),
    )?;
    store_jwt_access_token(&token_store, &token)?;

    let validator =
        TokenValidator::with_policy(token_store, key_manager, SecurityPolicy::default())
            .with_jwt_access_tokens_enabled(true)
            .with_issuer(Some(issuer.to_string()));

    let err = must_err!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "unknown payload backend override must fail closed",
    );

    if let Some(prev) = previous {
        std::env::set_var(key, prev);
    } else {
        std::env::remove_var(key);
    }

    assert_eq!(
        err,
        "access token parser backend misconfigured: unsupported raw JSON backend for jwt-access-token-payload"
    );
    Ok(())
}
