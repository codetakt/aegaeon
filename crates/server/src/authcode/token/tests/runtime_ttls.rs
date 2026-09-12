#[test]
fn runtime_ttls_configure_token_issuer_and_authorization_code_expiry() -> TestResult {
    let _lock = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|_| "token issuer env guard should lock".to_string())?;

    let issuer = TokenIssuer::new_process_local_with_ttls_for_tests(
        Arc::new(InMemoryKeyManager::new()),
        17,
        19,
        2,
    );

    assert_eq!(issuer.access_token_ttl_secs(), 17);
    assert_eq!(issuer.refresh_token_ttl_secs(), 19);
    assert_eq!(issuer.authorization_code_ttl_secs(), 2);

    let issued_before = SystemTime::now();
    let (code, _) = must_ok!(
        issuer.issue_authorization_code(authorization_request("read", None), "user123".into()),
        "authorization code",
    );
    let stored = must_ok!(
        issuer.code_store.try_get_code(&code),
        "stored authorization code lookup",
    );
    let stored = must_some!(stored, "authorization code should be stored");
    let ttl = stored
        .expires_at
        .duration_since(issued_before)
        .map_err(|error| {
            format!("configured authorization code should expire after issuance: {error:?}")
        })?;

    assert!(
        (2..=5).contains(&ttl.as_secs()),
        "authorization code ttl should be derived from runtime config, got {ttl:?}"
    );
    Ok(())
}

#[test]
fn shared_store_token_issuer_constructor_does_not_read_runtime_policy_env() -> TestResult {
    let _lock = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|_| "token issuer env guard should lock".to_string())?;
    let _auth_code_redis = EnvVarGuard::new(
        "AEGAEON_AUTH_CODE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _token_redis = EnvVarGuard::new(
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _jwt_access = EnvVarGuard::new("AEGAEON_ENABLE_JWT_ACCESS_TOKENS", Some("maybe"));
    let namespace = crate::config::RuntimeStateNamespace::for_tests("token-runtime-test");

    let issuer = must_ok!(
        TokenIssuer::try_from_shared_store_env_with_ttls(
            Arc::new(InMemoryKeyManager::new()),
            17,
            19,
            2,
            &namespace,
        ),
        "shared-store token issuer constructor must not read JWT runtime-policy env",
    );

    assert!(
        !issuer.jwt_access_tokens_enabled,
        "shared-store constructor leaves runtime policy to the caller"
    );
    Ok(())
}

#[test]
fn runtime_ttls_reject_unbounded_authorization_code_lifetime() -> TestResult {
    let namespace = crate::config::RuntimeStateNamespace::for_tests("token-runtime-ttl-test");
    let err = must_err!(
        TokenIssuer::try_from_shared_store_env_with_ttls(
        Arc::new(InMemoryKeyManager::new()),
        17,
        19,
        crate::config::MAX_AUTHORIZATION_CODE_TTL_SECS + 1,
        &namespace,
        ),
        "unbounded authorization-code TTL must fail closed"
    );

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. }
            if key == "authorization_code_time_to_live_seconds"
    ));
    Ok(())
}

#[tokio::test]
async fn token_exchange_target_root_caps_initial_issue_after_ttl_increase() -> TestResult {
    for asynchronous in [false, true] {
    let policy = must_ok!(serde_json::from_value(serde_json::json!({
        "version":1, "targets":[{"audience":"api","resourceAliases":[]}],
        "rules":[{"clientId":"test_client","sourceAudience":"test_client","targetAudience":"api",
            "scopes":[{"targetScope":"api.read","sourceScopes":["read"]}],"defaultScopes":["api.read"]}]
    })), "exchange policy");
    let mut issuer = TokenIssuer::new_process_local_with_ttls_for_tests(
        Arc::new(InMemoryKeyManager::new()), 10, 20, 60,
    ).with_token_exchange_policy(policy).with_issuer("https://issuer.example".into());
    let (code, _) = must_ok!(issuer.issue_authorization_code_with_local_profile(AuthorizationCodeIssueInput {
        exchange_scope_ceiling: vec!["api.read".into()],
        ..AuthorizationCodeIssueInput::new(authorization_request("read offline_access", None), "user123".into(), true, 0)
    }), "code");
    let stored = must_some!(must_ok!(issuer.code_store.try_get_code(&code), "code lookup"), "code exists");
    let root = must_some!(stored.exchange_grant.as_ref().and_then(|grant| grant.root()), "root exists").clone();
    // An administrator changes TTLs between authorization and redemption.
    issuer.access_token_ttl_secs = 3600;
    issuer.refresh_token_ttl_secs = 7200;
    let request = token_request_for_code(code, None);
    let response = if asynchronous {
        issuer.exchange_code_for_tokens_bound_with_grant_policy_async(request, None, None, true, true).await?
    } else { issuer.exchange_code_for_tokens(request, None)? };

    let TokenResponse::Success { access_token, expires_in, refresh_token: Some(refresh_token), .. } = response else {
        fail_test!("expected offline grant: {response:?}");
    };
    let access = must_some!(must_ok!(issuer.token_store.try_verify_access_token(&access_token), "access lookup"), "access exists");
    assert_eq!(expires_in, access.expires_in, "response must report the actual root-bounded lifetime");
    let refresh = must_some!(must_ok!(issuer.token_store.try_get_refresh_token(&refresh_token), "refresh lookup"), "refresh exists");
    assert!(access.created_at + Duration::from_secs(access.expires_in) <= root.expires_at);
    assert!(refresh.expires_at <= root.expires_at);
    assert_eq!(access.exchange_root.as_ref(), Some(&root));
    }
    Ok(())
}
