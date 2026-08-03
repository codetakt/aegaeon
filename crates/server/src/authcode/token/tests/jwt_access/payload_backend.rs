#[test]
fn test_jwt_access_token_validator_accepts_verified_structural_payload_backend() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    if raw_json_structural_parser_unavailable(
        br#"{"iss":"https://auth.example.com","sub":"client","aud":"client","iat":1,"exp":2,"jti":"test-jti"}"#,
    ) {
        return Ok(());
    }

    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::JwtAccessTokenPayload,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, "verified-structural-v1");

    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();

    let payload = json!({
        "iss": issuer,
        "sub": "client",
        "aud": "client",
        "client_id": "client",
        "iat": unix_epoch_now_secs(),
        "exp": unix_epoch_now_secs().saturating_add(300),
        "jti": "test-jti"
    });
    let token = must_ok!(
        sign_jwt(&payload, key_manager.as_ref(), ACCESS_TOKEN_TYP),
        "sign token",
    );
    store_jwt_access_token(&token_store, &token)?;

    let validator =
        TokenValidator::with_policy(token_store, key_manager, SecurityPolicy::default())
            .with_jwt_access_tokens_enabled(true)
            .with_issuer(Some(issuer.to_string()));

    let access = must_ok!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "verified structural payload backend should accept valid token",
    );

    if let Some(prev) = previous {
        std::env::set_var(key, prev);
    } else {
        std::env::remove_var(key);
    }

    assert_eq!(access.client_id, "client");
    assert_eq!(access.user_id, "client");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_negative_exp_with_verified_structural_payload_backend() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    if raw_json_structural_parser_unavailable(
        br#"{"iss":"https://auth.example.com","sub":"client","aud":"client","iat":1,"exp":-1,"jti":"test-jti"}"#,
    ) {
        return Ok(());
    }

    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::JwtAccessTokenPayload,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, "verified-structural-v1");

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
            "exp":-1,
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
        "negative exp must map to invalid_token_exp under the promoted payload backend",
    );

    if let Some(prev) = previous {
        std::env::set_var(key, prev);
    } else {
        std::env::remove_var(key);
    }

    assert_eq!(err, "invalid_token_exp");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_removed_serde_payload_backend() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::JwtAccessTokenPayload,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, "serde-compat");

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
            "aud":["client",7],
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
        "removed serde payload backend must fail closed",
    );

    if let Some(prev) = previous {
        std::env::set_var(key, prev);
    } else {
        std::env::remove_var(key);
    }

    assert!(
        err.contains("access token parser backend misconfigured"),
        "unexpected error for removed serde payload backend: {err}"
    );
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_non_string_aud_array_with_structural_payload_backend() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    if raw_json_structural_parser_unavailable(
        br#"{"iss":"https://auth.example.com","sub":"client","aud":["client",7],"iat":1,"exp":2,"jti":"test-jti"}"#,
    ) {
        return Ok(());
    }

    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::JwtAccessTokenPayload,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, "verified-structural-v1");

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
            "aud":["client",7],
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
        "non-string audience array elements must fail closed under structural parsing",
    );

    if let Some(prev) = previous {
        std::env::set_var(key, prev);
    } else {
        std::env::remove_var(key);
    }

    assert_eq!(err, "invalid_token_audience");
    Ok(())
}
