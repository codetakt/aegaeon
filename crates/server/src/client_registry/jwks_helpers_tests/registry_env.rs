use super::*;

#[test]
fn client_registry_process_local_test_helper_does_not_read_replay_redis_env() -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis = EnvVarGuard::new(
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        Some("not a url"),
    );
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("not a url"));

    let _registry = ClientRegistry::new_process_local_for_tests();
    Ok(())
}

#[test]
fn client_registry_process_local_test_helper_does_not_read_client_assertion_policy_env(
) -> TestResult {
    let _lock = env_lock()?;
    let _allowed = EnvVarGuard::new("AEGAEON_CLIENT_JWT_ALLOWED_ALGS", Some("HS256"));

    let _registry = ClientRegistry::new_process_local_for_tests();
    Ok(())
}

#[test]
fn client_registry_process_local_test_helper_uses_registry_local_jwks_runtime_state() {
    let first = ClientRegistry::new_process_local_for_tests();
    let second = ClientRegistry::new_process_local_for_tests();

    assert!(
        !Arc::ptr_eq(&first.jwks_state.inner, &second.jwks_state.inner),
        "process-local test registries must not share process-global JWKS runtime state"
    );
}

#[test]
fn client_registry_from_shared_store_env_with_runtime_policy_ignores_assertion_policy_env(
) -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis = EnvVarGuard::new(
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        Some("redis://127.0.0.1/0"),
    );
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("redis://127.0.0.1/1"));
    let _allowed = EnvVarGuard::new("AEGAEON_CLIENT_JWT_ALLOWED_ALGS", Some("HS256"));
    let _require_kid = EnvVarGuard::new("AEGAEON_CLIENT_JWT_REQUIRE_KID", Some("maybe"));
    let too_large = (MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS + 1).to_string();
    let _private_key_window = EnvVarGuard::new("AEGAEON_PKJWT_JTI_WINDOW_SECS", Some(&too_large));
    let _jwt_bearer_window =
        EnvVarGuard::new("AEGAEON_JWT_BEARER_JTI_WINDOW_SECS", Some(&too_large));

    let registry = test_context(
        ClientRegistry::from_shared_store_env_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-env-test"),
        ),
        "explicit assertion policy must override ambient policy env",
    )?;

    assert_eq!(
        registry.client_assertion_policy.allowed_algorithms,
        ClientAssertionRuntimePolicy::default().allowed_algorithms
    );
    Ok(())
}

#[test]
fn client_registry_from_shared_store_env_with_runtime_policy_ignores_managed_jwks_policy_env(
) -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis = EnvVarGuard::new(
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        Some("redis://127.0.0.1/0"),
    );
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("redis://127.0.0.1/1"));
    let _timeout = EnvVarGuard::new("AEGAEON_JWKS_HTTP_TIMEOUT_SECS", Some("not-a-number"));
    let _max_body = EnvVarGuard::new("AEGAEON_JWKS_MAX_BODY_BYTES", Some("0"));
    let _retries = EnvVarGuard::new("AEGAEON_JWKS_HTTP_RETRIES", Some("99"));

    let jwks_policy = JwksRuntimePolicy {
        http_timeout_secs: 7,
        max_body_bytes: 12345,
        http_retries: 3,
        ..JwksRuntimePolicy::default()
    };
    let registry = test_context(
        ClientRegistry::from_shared_store_env_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            jwks_policy,
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-env-test"),
        ),
        "explicit runtime policy must override ambient JWKS policy env",
    )?;

    assert_eq!(registry.jwks_policy.http_timeout_secs, 7);
    assert_eq!(registry.jwks_policy.max_body_bytes, 12345);
    assert_eq!(registry.jwks_policy.http_retries, 3);
    Ok(())
}

#[test]
fn client_registry_shared_store_constructor_rejects_invalid_replay_redis_url() -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis = EnvVarGuard::new(
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        Some("not a url"),
    );
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("redis://127.0.0.1/1"));

    match test_err(
        ClientRegistry::from_shared_store_env_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-env-test"),
        ),
        "invalid client assertion replay Redis URL must be rejected",
    )? {
        ClientRegistryInitError::Config(ConfigError::InvalidValue { key, .. })
            if key == "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL" =>
        {
            Ok(())
        }
        err => Err(format!(
            "unexpected client assertion replay Redis URL rejection: {err:?}"
        )),
    }
}

#[test]
fn client_registry_shared_store_constructor_requires_shared_jwks_runtime_state() -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis =
        EnvVarGuard::new("AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL", None);
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, None);

    assert!(matches!(
        ClientRegistry::from_shared_store_env_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-env-test"),
        ),
        Err(ClientRegistryInitError::Config(ConfigError::InvalidValue { key, .. }))
            if key == JWKS_REDIS_URL_ENV
    ));
    Ok(())
}

#[test]
fn client_registry_shared_store_constructor_requires_shared_replay_store() -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis =
        EnvVarGuard::new("AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL", None);
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("redis://127.0.0.1/"));

    assert!(matches!(
        ClientRegistry::from_shared_store_env_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-env-test"),
        ),
        Err(ClientRegistryInitError::Config(ConfigError::InvalidValue { key, .. }))
            if key == "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL"
    ));
    Ok(())
}

#[test]
fn seeded_test_clients_require_shared_replay_store() -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis =
        EnvVarGuard::new("AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL", None);
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("redis://127.0.0.1/"));

    assert!(matches!(
        ClientRegistry::try_with_test_clients_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-env-test"),
        ),
        Err(ClientRegistryInitError::Config(ConfigError::InvalidValue { key, .. }))
            if key == "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL"
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn client_registry_shared_store_constructor_rejects_non_unicode_replay_redis_without_fallback(
) -> TestResult {
    use std::os::unix::ffi::OsStringExt;

    let _lock = env_lock()?;
    let key = "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL";
    let _client_assertion_redis = EnvVarGuard::new(key, None);
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", Some("redis://127.0.0.1/"));
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("redis://127.0.0.1/1"));
    std::env::set_var(
        key,
        std::ffi::OsString::from_vec(vec![0x72, 0x65, 0x64, 0x80]),
    );

    assert!(matches!(
        ClientRegistry::from_shared_store_env_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-env-test"),
        ),
        Err(ClientRegistryInitError::Config(ConfigError::NonUnicode { key: err_key }))
            if err_key == key
    ));
    Ok(())
}

#[test]
fn client_registry_shared_store_constructor_rejects_invalid_jwks_redis_url() -> TestResult {
    let _lock = env_lock()?;
    let _client_assertion_redis =
        EnvVarGuard::new("AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL", None);
    let _dpop_redis = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _jwks_redis = EnvVarGuard::new(JWKS_REDIS_URL_ENV, Some("not a url"));

    match test_err(
        ClientRegistry::from_shared_store_env_with_runtime_policy(
            ClientAssertionRuntimePolicy::default(),
            JwksRuntimePolicy::default(),
            &crate::config::RuntimeStateNamespace::for_tests("client-registry-env-test"),
        ),
        "invalid JWKS Redis URL must be rejected",
    )? {
        ClientRegistryInitError::Config(ConfigError::InvalidValue { key, .. })
            if key == JWKS_REDIS_URL_ENV =>
        {
            Ok(())
        }
        err => Err(format!("unexpected JWKS Redis URL rejection: {err:?}")),
    }
}
