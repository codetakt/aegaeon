#[test]
fn malformed_boolean_env_returns_error_without_panic() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _dpop = EnvVarGuard::new("AEGAEON_DPOP_STRICT", Some("maybe"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);
    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_DPOP_STRICT" && reason.contains("AEGAEON_DPOP_STRICT")
    ));
}

#[test]
fn server_config_requires_state_by_default() {
    let _lock = env_lock();
    let _db = required_database_url();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _require_state = EnvVarGuard::new("AEGAEON_REQUIRE_STATE", None);

    let result = panic::catch_unwind(ServerConfig::try_from_env);
    assert!(
        result.is_ok_and(|config| config.is_ok_and(|config| config.require_state)),
        "authorization requests must require state unless explicitly disabled"
    );
}

#[cfg(unix)]
#[test]
fn database_config_rejects_non_unicode_primary_url() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new_os_string(
        "AEGAEON_DATABASE_URL",
        Some(OsString::from_vec(vec![0x66, 0x80])),
    );

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::NonUnicode { key })) if key == "AEGAEON_DATABASE_URL"
    ));
}

#[test]
fn database_config_requires_database_url() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new("AEGAEON_DATABASE_URL", None);

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_DATABASE_URL" && reason.contains("PostgreSQL is required")
    ));
}

#[test]
fn database_config_rejects_standard_tooling_url_without_namespaced_url() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new("AEGAEON_DATABASE_URL", None);
    let _tooling = EnvVarGuard::new("DATABASE_URL", Some("postgres://tooling"));

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_DATABASE_URL" && reason.contains("set AEGAEON_DATABASE_URL")
    ));
}

#[test]
fn database_config_rejects_empty_primary_url() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new("AEGAEON_DATABASE_URL", Some("  "));

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_DATABASE_URL" && reason.contains("must not be empty")
    ));
}

#[test]
fn server_config_rejects_removed_database_runtime_envs() {
    for (key, reason_fragment) in [
        ("AEGAEON_DB_ENABLED", "PostgreSQL is mandatory"),
        ("AEGAEON_CONFIG_AUTHORITY", "selector was removed"),
        (
            "AEGAEON_RUNTIME_CONFIG_MONITOR_INTERVAL_SECS",
            "managed by the active database policy",
        ),
        (
            "AEGAEON_RUNTIME_CLIENT_SYNC_INTERVAL_SECS",
            "managed by the active database policy",
        ),
        (
            "AEGAEON_ADMIN_API_KEY",
            "legacy /admin API key environment variable was removed",
        ),
        (
            "AEGAEON_CSRF_REDIS_URL",
            "shared CSRF Redis fallback was removed",
        ),
        (
            "AEGAEON_RATE_LIMIT_REDIS_URL",
            "shared rate-limit Redis fallback was removed",
        ),
        (
            "AEGAEON_DCR_EVERPARSE_RUNTIME",
            "managed by the active database policy",
        ),
        (
            "AEGAEON_REQUEST_OBJECT_EVERPARSE_RUNTIME",
            "managed by the active database policy",
        ),
        (
            "AEGAEON_JOSE_HEADER_MAXLEN",
            "managed by the active database policy",
        ),
        (
            "AEGAEON_EXPOSE_METRICS_ON_MAIN",
            "main-server metrics exposure was removed",
        ),
        (
            "AEGAEON_DEPLOYMENT_MODE",
            "deployment mode selector was removed",
        ),
        (
            "AEGAEON_ALLOW_UNSHARED_RUNTIME_STATE",
            "legacy acknowledgement was removed",
        ),
        (
            "AEGAEON_ALLOW_EPHEMERAL_RUNTIME_STATE",
            "legacy ephemeral runtime-state acknowledgement was removed",
        ),
    ] {
        let _lock = env_lock();
        let _runtime_env = database_backed_runtime_env();
        let _removed = EnvVarGuard::new(key, Some("1"));

        let result = panic::catch_unwind(ServerConfig::try_from_env);

        assert!(
            matches!(
                result,
                Ok(Err(ConfigError::InvalidValue { key: err_key, reason, .. }))
                    if err_key == key && reason.contains(reason_fragment)
            ),
            "{key} must fail closed when present"
        );
    }
}

#[test]
fn server_config_requires_auth_code_and_token_store_same_redis_url() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _auth_code = EnvVarGuard::new(
        "AEGAEON_AUTH_CODE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _token_store =
        EnvVarGuard::new("AEGAEON_TOKEN_STORE_REDIS_URL", Some("redis://127.0.0.1/1"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_TOKEN_STORE_REDIS_URL"
                && reason.contains("must reference the same Redis endpoint")
    ));
}

#[test]
fn server_config_accepts_atomic_stores_on_same_canonical_redis_endpoint() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _auth_code = EnvVarGuard::new(
        "AEGAEON_AUTH_CODE_REDIS_URL",
        Some("redis://writer:secret@127.0.0.1/0"),
    );
    let _token_store = EnvVarGuard::new(
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        Some("redis://reader:secret@127.0.0.1:6379/"),
    );
    let _par = EnvVarGuard::new("AEGAEON_PAR_REDIS_URL", Some("redis://127.0.0.1:6379"));
    let _request_object_jti = EnvVarGuard::new(
        "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _oidc_logout = EnvVarGuard::new(
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        Some("redis://127.0.0.1/0"),
    );

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(
        matches!(result, Ok(Ok(_))),
        "canonical Redis endpoint equivalence must not depend on raw URL credential/default-port spelling"
    );
}

#[test]
fn server_config_requires_oidc_logout_and_token_store_same_redis_url() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _auth_code = EnvVarGuard::new(
        "AEGAEON_AUTH_CODE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _token_store = EnvVarGuard::new(
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _oidc_logout = EnvVarGuard::new(
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        Some("redis://127.0.0.1/1"),
    );

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL"
                && reason.contains("logout-session fan-out atomically")
    ));
}

#[test]
fn server_config_requires_par_and_auth_code_same_redis_url() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _auth_code = EnvVarGuard::new(
        "AEGAEON_AUTH_CODE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _token_store = EnvVarGuard::new(
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _oidc_logout = EnvVarGuard::new(
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        Some("redis://127.0.0.1/0"),
    );
    let _par = EnvVarGuard::new("AEGAEON_PAR_REDIS_URL", Some("redis://127.0.0.1/1"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_PAR_REDIS_URL"
                && reason.contains("consume PAR request_uri atomically")
    ));
}

#[test]
fn server_config_requires_request_object_jti_and_auth_code_same_redis_url() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _auth_code = EnvVarGuard::new(
        "AEGAEON_AUTH_CODE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _token_store = EnvVarGuard::new(
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let _oidc_logout = EnvVarGuard::new(
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        Some("redis://127.0.0.1/0"),
    );
    let _request_object_jti = EnvVarGuard::new(
        "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        Some("redis://127.0.0.1/1"),
    );

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL"
                && reason.contains("consume direct Request Object jti atomically")
    ));
}

#[test]
fn server_config_rejects_raw_json_backend_override_envs() {
    for key in raw_json_backend_override_env_keys() {
        let _lock = env_lock();
        let _runtime_env = database_backed_runtime_env();
        let _override = EnvVarGuard::new(key, Some("serde-compat"));

        let result = panic::catch_unwind(ServerConfig::try_from_env);

        assert!(
            matches!(
                result,
                Ok(Err(ConfigError::InvalidValue { key: err_key, reason, .. }))
                    if err_key == key
                        && reason.contains("raw JSON backend selection is fixed")
            ),
            "{key} must fail closed when present in server startup env"
        );
    }
}

#[test]
fn database_config_accepts_postgresql_scheme() -> ConfigTestResult {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new(
        "AEGAEON_DATABASE_URL",
        Some(" postgresql://aegaeon:secret@db.example/aegaeon?sslmode=verify-full "),
    );

    let cfg = must_ok!(
        DatabaseConfig::try_from_env(),
        "postgresql scheme database URL",
    );

    assert_eq!(
        cfg.url(),
        "postgresql://aegaeon:secret@db.example/aegaeon?sslmode=verify-full"
    );
    Ok(())
}

#[test]
fn database_config_accepts_loopback_without_sslmode() -> ConfigTestResult {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new(
        "AEGAEON_DATABASE_URL",
        Some("postgres://aegaeon:secret@127.0.0.1/aegaeon"),
    );

    let cfg = must_ok!(
        DatabaseConfig::try_from_env(),
        "loopback PostgreSQL database URL",
    );

    assert_eq!(
        cfg.url(),
        "postgres://aegaeon:secret@127.0.0.1/aegaeon"
    );
    Ok(())
}

#[test]
fn database_config_requires_tls_for_non_loopback_database_url() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new(
        "AEGAEON_DATABASE_URL",
        Some("postgresql://aegaeon:secret@db.example/aegaeon"),
    );

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, value, reason }))
            if key == "AEGAEON_DATABASE_URL"
                && value == "<redacted>"
                && reason.contains("non-loopback PostgreSQL database URLs must include sslmode")
    ));
}

#[test]
fn database_config_rejects_weak_non_loopback_sslmode() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new(
        "AEGAEON_DATABASE_URL",
        Some("postgresql://aegaeon:secret@db.example/aegaeon?sslmode=prefer"),
    );

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, value, reason }))
            if key == "AEGAEON_DATABASE_URL"
                && value == "prefer"
                && reason.contains("sslmode=require")
    ));
}

#[test]
fn database_config_rejects_duplicate_sslmode() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new(
        "AEGAEON_DATABASE_URL",
        Some("postgresql://aegaeon:secret@db.example/aegaeon?sslmode=require&sslmode=verify-full"),
    );

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, value, reason }))
            if key == "AEGAEON_DATABASE_URL"
                && value == "<redacted>"
                && reason.contains("at most one sslmode")
    ));
}

#[test]
fn database_config_rejects_hostless_database_url() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new(
        "AEGAEON_DATABASE_URL",
        Some("postgresql:///aegaeon?sslmode=require"),
    );

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, value, reason }))
            if key == "AEGAEON_DATABASE_URL"
                && value == "<redacted>"
                && reason.contains("explicit host")
    ));
}

#[test]
fn database_config_rejects_non_postgresql_scheme() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new("AEGAEON_DATABASE_URL", Some("mysql://db.example/aegaeon"));

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, value, reason }))
            if key == "AEGAEON_DATABASE_URL"
                && value == "mysql"
                && reason.contains("scheme must be postgres:// or postgresql://")
    ));
}

#[test]
fn database_config_rejects_malformed_database_url_without_echoing_secret() {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new(
        "AEGAEON_DATABASE_URL",
        Some("postgres://user:secret with spaces"),
    );

    let result = panic::catch_unwind(DatabaseConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, value, reason }))
            if key == "AEGAEON_DATABASE_URL"
                && value == "<redacted>"
                && reason.contains("valid postgres:// or postgresql:// URL")
    ));
}

#[test]
fn malformed_trusted_proxy_entry_returns_error_without_panic() {
    let _lock = env_lock();
    let _trusted = EnvVarGuard::new("AEGAEON_TRUSTED_PROXIES", Some("127.0.0.1,not-an-ip"));

    let result = panic::catch_unwind(TransportSecurityConfig::try_from_env);
    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidIpNet { key, .. })) if key == "AEGAEON_TRUSTED_PROXIES"
    ));
}

#[test]
fn transport_config_rejects_removed_secure_proto_fallback_env() {
    let _lock = env_lock();
    let _current = EnvVarGuard::new("AEGAEON_REQUIRE_TLS_PROXY", None);
    let _legacy = EnvVarGuard::new("AEGAEON_ENFORCE_SECURE_PROTO", Some("1"));

    let result = panic::catch_unwind(TransportSecurityConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_ENFORCE_SECURE_PROTO"
                && reason.contains("AEGAEON_REQUIRE_TLS_PROXY")
    ));
}

#[test]
fn transport_config_rejects_zero_proxy_chain_length() {
    let _lock = env_lock();
    let _chain_length = EnvVarGuard::new("AEGAEON_ALLOW_PROXY_CHAIN_LENGTH", Some("0"));

    let result = panic::catch_unwind(TransportSecurityConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidNumberRange { key, expectation, .. }))
            if key == "AEGAEON_ALLOW_PROXY_CHAIN_LENGTH"
                && expectation.contains("1..=255")
    ));
}

#[test]
fn env_num_with_rejects_malformed_or_out_of_range_values() {
    let _lock = env_lock();

    let malformed = EnvVarGuard::new("AEGAEON_CONFIG_TEST_NUM", Some("not-a-number"));
    assert!(
        panic::catch_unwind(|| {
            try_env_num_with(
                "AEGAEON_CONFIG_TEST_NUM",
                10u64,
                |value| value > 0 && value <= 60,
                "a value in 1..=60",
            )
        })
        .is_ok_and(|result| result.is_err()),
        "malformed numeric env values must return errors without panicking"
    );
    drop(malformed);

    let _out_of_range = EnvVarGuard::new("AEGAEON_CONFIG_TEST_NUM", Some("61"));
    assert!(
        panic::catch_unwind(|| {
            try_env_num_with(
                "AEGAEON_CONFIG_TEST_NUM",
                10u64,
                |value| value > 0 && value <= 60,
                "a value in 1..=60",
            )
        })
        .is_ok_and(|result| result.is_err()),
        "out-of-range numeric env values must return errors without panicking"
    );
}

#[test]
fn authorization_code_ttl_no_longer_falls_back_to_state_nonce_alias() -> ConfigTestResult {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _primary = EnvVarGuard::new("AEGAEON_AUTHORIZATION_CODE_TTL_SECS", None);
    let _legacy = EnvVarGuard::new("AEGAEON_STATE_NONCE_TTL_SECS", Some("2"));

    let err = must_err!(
        ServerConfig::try_from_env(),
        "removed state/nonce TTL alias must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_STATE_NONCE_TTL_SECS"
                && reason.contains("AEGAEON_STATE_NONCE_TTL_SECS")
    ));
    Ok(())
}

#[test]
fn introspection_client_auth_no_longer_falls_back_to_removed_alias() -> ConfigTestResult {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _primary = EnvVarGuard::new("AEGAEON_REQUIRE_CLIENT_AUTH_INTROSPECTION", None);
    let _legacy = EnvVarGuard::new("AEGAEON_REQUIRE_CLIENT_AUTH_INTROSPECT", Some("0"));

    let err = must_err!(
        ServerConfig::try_from_env(),
        "removed introspection auth alias must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_REQUIRE_CLIENT_AUTH_INTROSPECT"
                && reason.contains("AEGAEON_REQUIRE_CLIENT_AUTH_INTROSPECT")
    ));
    Ok(())
}

#[test]
fn jwt_bearer_window_no_longer_falls_back_to_private_key_jwt_window() -> ConfigTestResult {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _private_key_jwt_window = EnvVarGuard::new("AEGAEON_PKJWT_JTI_WINDOW_SECS", Some("120"));
    let _jwt_bearer_window = EnvVarGuard::new("AEGAEON_JWT_BEARER_JTI_WINDOW_SECS", None);

    let err = must_err!(
        ServerConfig::try_from_env(),
        "removed private_key_jwt replay env must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_PKJWT_JTI_WINDOW_SECS"
                && reason.contains("AEGAEON_PKJWT_JTI_WINDOW_SECS")
    ));
    Ok(())
}

#[test]
fn token_ttl_policy_rejects_unbounded_values() {
    let _lock = env_lock();

    let access_ttl = (MAX_ACCESS_TOKEN_TTL_SECS + 1).to_string();
    let access = EnvVarGuard::new("AEGAEON_CONFIG_TEST_ACCESS_TOKEN_TTL", Some(&access_ttl));
    assert!(
        panic::catch_unwind(|| {
            try_env_num_with(
                "AEGAEON_CONFIG_TEST_ACCESS_TOKEN_TTL",
                3600u64,
                valid_access_token_ttl_secs,
                "a value in 1..=86400 seconds",
            )
        })
        .is_ok_and(|result| result.is_err()),
        "access-token TTL above the bounded policy must return an error"
    );
    drop(access);

    let refresh_ttl = (MAX_REFRESH_TOKEN_TTL_SECS + 1).to_string();
    let _refresh = EnvVarGuard::new("AEGAEON_CONFIG_TEST_REFRESH_TOKEN_TTL", Some(&refresh_ttl));
    assert!(
        panic::catch_unwind(|| {
            try_env_num_with(
                "AEGAEON_CONFIG_TEST_REFRESH_TOKEN_TTL",
                86400u64,
                valid_refresh_token_ttl_secs,
                "a value in 1..=7776000 seconds",
            )
        })
        .is_ok_and(|result| result.is_err()),
        "refresh-token TTL above the bounded policy must return an error"
    );
}

#[test]
fn jwt_leeway_policy_rejects_unbounded_values() {
    assert!(!valid_jwt_leeway_secs(MAX_JWT_LEEWAY_SECS + 1));
    assert!(valid_jwt_leeway_secs(MAX_JWT_LEEWAY_SECS));
}

#[test]
fn dpop_nonce_ttl_policy_rejects_zero_and_unbounded_values() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();

    let zero = EnvVarGuard::new("AEGAEON_DPOP_NONCE_TTL_SECS", Some("0"));
    assert!(
        matches!(
            panic::catch_unwind(ServerConfig::try_from_env),
            Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
                if key == "AEGAEON_DPOP_NONCE_TTL_SECS"
                    && reason.contains("AEGAEON_DPOP_NONCE_TTL_SECS")
        ),
        "removed DPoP nonce TTL env must fail closed"
    );
    drop(zero);

    let ttl = (MAX_DPOP_NONCE_TTL_SECS + 1).to_string();
    let _too_large = EnvVarGuard::new("AEGAEON_DPOP_NONCE_TTL_SECS", Some(&ttl));
    assert!(
        panic::catch_unwind(ServerConfig::try_from_env).is_ok_and(|result| result.is_err()),
        "DPoP nonce TTL above the bounded policy must return an error"
    );
}

#[test]
fn dpop_iat_window_policy_rejects_zero_and_unbounded_values() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();

    let zero = EnvVarGuard::new("AEGAEON_DPOP_IAT_WINDOW_SECS", Some("0"));
    assert!(
        matches!(
            panic::catch_unwind(ServerConfig::try_from_env),
            Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
                if key == "AEGAEON_DPOP_IAT_WINDOW_SECS"
                    && reason.contains("AEGAEON_DPOP_IAT_WINDOW_SECS")
        ),
        "removed DPoP iat window env must fail closed"
    );
    drop(zero);

    let window = (MAX_DPOP_IAT_WINDOW_SECS + 1).to_string();
    let _too_large = EnvVarGuard::new("AEGAEON_DPOP_IAT_WINDOW_SECS", Some(&window));
    assert!(
        panic::catch_unwind(ServerConfig::try_from_env).is_ok_and(|result| result.is_err()),
        "DPoP iat window above the bounded policy must return an error"
    );
}

#[test]
fn crypto_profile_env_is_rejected_under_database_backed_runtime_env() {
    let _lock = env_lock();
    let _db = required_database_url();
    let _profile = EnvVarGuard::new("AEGAEON_CRYPTO_PROFILE", Some("invalid-profile"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_CRYPTO_PROFILE"
                && reason.contains("AEGAEON_CRYPTO_PROFILE")
    ));
}

#[test]
fn malformed_mtls_metadata_toggle_returns_error_without_panic() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _mtls = EnvVarGuard::new("AEGAEON_MTLS_ENABLED", Some("maybe"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_MTLS_ENABLED" && reason.contains("AEGAEON_MTLS_ENABLED")
    ));
}
