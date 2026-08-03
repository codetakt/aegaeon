#[test]
fn test_jwt_access_token_validator_rejects_duplicate_payload_claim_keys() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
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
            "sub":"evil-client",
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
        "duplicate payload claims must fail closed",
    );
    assert_eq!(err, "Invalid token signature");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_trailing_payload_bytes() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
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
        } trailing"#,
        key_manager.as_ref(),
    )?;
    store_jwt_access_token(&token_store, &token)?;

    let validator =
        TokenValidator::with_policy(token_store, key_manager, SecurityPolicy::default())
            .with_jwt_access_tokens_enabled(true)
            .with_issuer(Some(issuer.to_string()));

    let err = must_err!(
        validator.validate_bearer_token(&format!("Bearer {token}")),
        "trailing payload bytes must fail closed",
    );
    assert_eq!(err, "Invalid token signature");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_duplicate_header_keys() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();

    let token = sign_raw_jwt_parts(
        &format!(
            r#"{{"alg":"HS256","typ":"at+jwt","kid":"{}","kid":"evil-kid"}}"#,
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
        "duplicate header keys must fail closed",
    );
    assert_eq!(err, "Invalid token signature");
    Ok(())
}

#[test]
fn test_jwt_access_token_validator_rejects_non_object_header_shape() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();

    let token = sign_raw_jwt_parts(
        r#"["HS256","at+jwt","kid"]"#,
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
        "non-object header payloads must fail closed",
    );
    assert_eq!(err, "Invalid token signature");
    Ok(())
}
