#[test]
fn test_jwt_access_token_validator_enforces_typ() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
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
        sign_jwt(&payload, key_manager.as_ref(), "JWT"),
        "sign token",
    );
    store_jwt_access_token(&token_store, &token)?;

    let validator =
        TokenValidator::with_policy(token_store, key_manager, SecurityPolicy::default())
            .with_jwt_access_tokens_enabled(true)
            .with_issuer(Some(issuer.to_string()));

    let err = must_err!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "invalid typ should be rejected",
    );
    assert_eq!(err, "invalid_token_typ");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_enforces_expiry_time() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();
    let now = unix_epoch_now_secs();
    let payload = json!({
        "iss": issuer,
        "sub": "client",
        "aud": "client",
        "client_id": "client",
        "iat": now.saturating_sub(300),
        "exp": now.saturating_sub(120),
        "jti": "expired-jti"
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

    let err = must_err!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "expired JWT access token must be rejected",
    );
    assert_eq!(err, "invalid_token_exp");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_future_iat() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();
    let now = unix_epoch_now_secs();
    let payload = json!({
        "iss": issuer,
        "sub": "client",
        "aud": "client",
        "client_id": "client",
        "iat": now.saturating_add(3600),
        "exp": now.saturating_add(7200),
        "jti": "future-iat-jti"
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

    let err = must_err!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "future iat JWT access token must be rejected",
    );
    assert_eq!(err, "invalid_token_iat");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_exp_before_iat() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();
    let now = unix_epoch_now_secs();
    let payload = json!({
        "iss": issuer,
        "sub": "client",
        "aud": "client",
        "client_id": "client",
        "iat": now.saturating_add(120),
        "exp": now.saturating_add(60),
        "jti": "exp-before-iat-jti"
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

    let err = must_err!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "JWT access token exp before iat must be rejected",
    );
    assert_eq!(err, "invalid_token_exp");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_exp_equal_iat() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();
    let timestamp = unix_epoch_now_secs().saturating_add(30);
    let payload = json!({
        "iss": issuer,
        "sub": "client",
        "aud": "client",
        "client_id": "client",
        "iat": timestamp,
        "exp": timestamp,
        "jti": "exp-equal-iat-jti"
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

    let err = must_err!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "JWT access token exp equal to iat must be rejected",
    );
    assert_eq!(err, "invalid_token_exp");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_enforces_key_manager_alg() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();

    let token = sign_raw_jwt_parts(
        &format!(
            r#"{{"alg":"PS256","typ":"{}","kid":"{}"}}"#,
            ACCESS_TOKEN_TYP,
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
        "wrong alg must be rejected even when the signature bytes verify",
    );
    assert_eq!(err, "Invalid token signature");
    Ok(())
}
