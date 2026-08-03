#[test]
fn management_database_bootstrap_rejects_startup_managed_policy_environment() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _trusted_proxy = EnvVarGuard::new("AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY", None);
    let _tls_validation = EnvVarGuard::new("AEGAEON_POLICY_REQUIRE_TLS_VALIDATION", None);
    let _dpop = EnvVarGuard::new("AEGAEON_DPOP_STRICT", Some("maybe"));
    let _sender = EnvVarGuard::new(
        "AEGAEON_POLICY_SENDER_CONSTRAINT",
        Some("not-a-sender-constraint"),
    );
    let _nonce_ttl = EnvVarGuard::new("AEGAEON_DPOP_NONCE_TTL_SECS", Some("0"));
    let _mtls = EnvVarGuard::new("AEGAEON_MTLS_ENABLED", Some("maybe"));
    let _supported = EnvVarGuard::new("AEGAEON_ACR_VALUES_SUPPORTED", Some("urn:pwd"));
    let _local = EnvVarGuard::new("AEGAEON_LOCAL_PASSWORD_ACR", Some("urn:mfa"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_DPOP_STRICT"
                && reason.contains("runtime policy")
                && reason.contains("management configuration snapshot")
                && reason.contains("AEGAEON_DPOP_STRICT")
                && reason.contains("AEGAEON_POLICY_SENDER_CONSTRAINT")
                && reason.contains("AEGAEON_ACR_VALUES_SUPPORTED")
    ));
}

#[test]
fn management_database_bootstrap_rejects_empty_startup_managed_policy_environment() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _empty_removed_policy_env = EnvVarGuard::new("AEGAEON_DPOP_STRICT", Some(""));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_DPOP_STRICT"
                && reason.contains("runtime policy")
                && reason.contains("AEGAEON_DPOP_STRICT")
    ));
}

#[test]
fn management_database_bootstrap_rejects_empty_oidc_startup_environment() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _empty_oidc_env = EnvVarGuard::new("AEGAEON_OIDC_ENABLED", Some(""));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_OIDC_ENABLED"
                && reason.contains("OIDC runtime policy")
                && reason.contains("AEGAEON_OIDC_ENABLED")
    ));
}

#[test]
fn management_database_bootstrap_rejects_management_control_plane_policy_environment() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _origin = EnvVarGuard::new(
        "AEGAEON_MANAGEMENT_ALLOWED_ORIGINS",
        Some("https://admin.example.com"),
    );
    let _issuer = EnvVarGuard::new("AEGAEON_MANAGEMENT_ISSUER_BASE_DOMAIN", Some("example.com"));
    let _ttl = EnvVarGuard::new("AEGAEON_MANAGEMENT_SESSION_TTL_SECS", Some("3600"));
    let _max = EnvVarGuard::new("AEGAEON_MANAGEMENT_MAX_SESSIONS", Some("100"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_MANAGEMENT_ALLOWED_ORIGINS"
                && reason.contains("runtime policy")
                && reason.contains("management configuration snapshot")
                && reason.contains("AEGAEON_MANAGEMENT_ALLOWED_ORIGINS")
                && reason.contains("AEGAEON_MANAGEMENT_ISSUER_BASE_DOMAIN")
                && reason.contains("AEGAEON_MANAGEMENT_SESSION_TTL_SECS")
                && reason.contains("AEGAEON_MANAGEMENT_MAX_SESSIONS")
    ));
}

#[test]
fn management_database_bootstrap_reads_system_transport_policy_environment() -> ConfigTestResult {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _trusted_proxy = EnvVarGuard::new("AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY", Some("0"));
    let _tls_proxy = EnvVarGuard::new("AEGAEON_REQUIRE_TLS_PROXY", Some("0"));
    let _proxy_mtls = EnvVarGuard::new("AEGAEON_REQUIRE_MTLS_FROM_PROXY", Some("0"));

    let cfg = must_ok!(
        ServerConfig::try_from_env(),
        "database bootstrap should parse transport policy",
    );

    assert!(!cfg.security_policy.enforce_trusted_proxy());
    assert!(!cfg.transport.require_tls_proxy);
    Ok(())
}

#[test]
fn management_database_bootstrap_rejects_disabled_tls_validation_invariant() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _tls_validation = EnvVarGuard::new("AEGAEON_POLICY_REQUIRE_TLS_VALIDATION", Some("0"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, .. }))
            if key == "AEGAEON_POLICY_REQUIRE_TLS_VALIDATION"
    ));
}

#[test]
fn management_database_rejects_removed_federation_op_env() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _enabled = EnvVarGuard::new("AEGAEON_FEDERATION_OP_ENABLED", Some("1"));
    let _entity_exp = EnvVarGuard::new("AEGAEON_FEDERATION_ENTITY_EXP_SECS", Some("1"));
    let _authority_hints = EnvVarGuard::new(
        "AEGAEON_FEDERATION_AUTHORITY_HINTS",
        Some("http://invalid.example.com"),
    );

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_FEDERATION_OP_ENABLED"
                && reason.contains("public OpenID Federation OP publication was removed")
    ));
}

#[test]
fn management_database_rejects_jwks_startup_policy_env() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _allow_reuse = EnvVarGuard::new("AEGAEON_JWKS_ALLOW_KID_REUSE", Some("1"));
    let _timeout = EnvVarGuard::new("AEGAEON_JWKS_HTTP_TIMEOUT_SECS", Some("9"));
    let _max_body = EnvVarGuard::new("AEGAEON_JWKS_MAX_BODY_BYTES", Some("131072"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_JWKS_ALLOW_KID_REUSE"
                && reason.contains("runtime policy")
                && reason.contains("AEGAEON_JWKS_ALLOW_KID_REUSE")
                && reason.contains("AEGAEON_JWKS_HTTP_TIMEOUT_SECS")
                && reason.contains("AEGAEON_JWKS_MAX_BODY_BYTES")
    ));
}

#[test]
fn management_database_rejects_removed_jwks_stale_env() {
    let _lock = env_lock();
    let _runtime_env = database_backed_runtime_env();
    let _stale_preference = EnvVarGuard::new("AEGAEON_JWKS_STALE_PREFERENCE", Some("shared_first"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_JWKS_STALE_PREFERENCE"
                && reason.contains("JWKS stale serving was removed")
    ));
}
