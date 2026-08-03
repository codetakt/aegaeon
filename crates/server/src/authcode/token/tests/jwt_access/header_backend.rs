#[test]
fn test_jwt_access_token_validator_accepts_verified_structural_header_backend() -> TestResult {
    let _guard = jwt_access_token_raw_json_env_guard()?;
    if raw_json_structural_parser_unavailable(br#"{"alg":"HS256","typ":"at+jwt","kid":"test"}"#)
    {
        return Ok(());
    }

    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::JwtAccessTokenHeader,
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
        "verified structural header backend should accept valid token",
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
fn test_jwt_access_token_validator_rejects_non_string_typ_with_verified_structural_header_backend() -> TestResult
{
    let _guard = jwt_access_token_raw_json_env_guard()?;
    if raw_json_structural_parser_unavailable(br#"{"alg":"HS256","typ":7,"kid":"test"}"#) {
        return Ok(());
    }

    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        RawJsonSurface::JwtAccessTokenHeader,
    );
    let previous = std::env::var(key).ok();
    std::env::set_var(key, "verified-structural-v1");

    let issuer = "https://auth.example.com";
    let key_manager: Arc<dyn KeyManager> = Arc::new(InMemoryKeyManager::new());
    let token_store = TokenStore::new_process_local_for_tests();

    let token = sign_raw_jwt_parts(
        &format!(
            r#"{{"alg":"HS256","typ":7,"kid":"{}"}}"#,
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
        "non-string typ must remain fail closed under the promoted header backend",
    );

    if let Some(prev) = previous {
        std::env::set_var(key, prev);
    } else {
        std::env::remove_var(key);
    }

    assert_eq!(err, "invalid_token_typ");
    Ok(())
}
