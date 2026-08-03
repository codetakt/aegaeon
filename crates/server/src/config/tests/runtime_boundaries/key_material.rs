use super::*;

#[test]
fn runtime_rejects_unmanaged_jwt_signing_key_material() {
    let _lock = env_lock();
    let _shared_stores = set_base_shared_runtime_store_env();
    let cfg = ServerConfig {
        enable_jwt_access_tokens: true,
        ..ServerConfig::default()
    };

    let result =
        cfg.validate_runtime_boundaries_with_key_material(false, false, true);

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, reason, .. })
            if key == "runtime_keys" && reason.contains("JWT access tokens")
    ));
}

#[test]
fn runtime_allows_database_backed_oauth_jwt_key_material() -> ConfigTestResult {
    let _lock = env_lock();
    let _shared_stores = set_base_shared_runtime_store_env();

    let cfg = ServerConfig {
        enable_jwt_access_tokens: true,
        enable_jwt_introspection: true,
        ..ServerConfig::default()
    };

    must_ok!(
        cfg.validate_runtime_boundaries_with_key_material(false, false, false),
        "database-backed OAuth JWT key material is shared",
    );
    Ok(())
}

#[test]
fn runtime_rejects_unmanaged_oidc_signing_key_material() {
    let _lock = env_lock();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _oidc_sessions = EnvVarGuard::new(
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let cfg = ServerConfig::default();

    let result =
        cfg.validate_runtime_boundaries_with_key_material(true, true, false);

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, reason, .. })
            if key == "runtime_keys" && reason.contains("OIDC ID Token signing")
    ));
}

#[test]
fn management_database_rejects_oidc_startup_key_material_env() {
    let _lock = env_lock();
    let _db = required_database_url();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _oidc = EnvVarGuard::new("AEGAEON_OIDC_ENABLED", Some("1"));
    let _signing_key = EnvVarGuard::new(
        "AEGAEON_OIDC_SIGNING_KEY_PEM",
        Some("legacy-startup-key-material"),
    );

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "AEGAEON_OIDC_SIGNING_KEY_PEM"
                && reason.contains("runtime_keys snapshot")
                && reason.contains("AEGAEON_OIDC_SIGNING_KEY_PEM")
    ));
}

#[test]
fn management_database_rejects_oidc_startup_policy_env_without_key_material() {
    let _lock = env_lock();
    let _db = required_database_url();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _oidc = EnvVarGuard::new("AEGAEON_OIDC_ENABLED", Some("1"));

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
fn runtime_rejects_unmanaged_oidc_request_object_decryption_key_material() {
    let _lock = env_lock();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _oidc_sessions = EnvVarGuard::new(
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let cfg = ServerConfig::default();

    let result =
        cfg.validate_runtime_boundaries_with_key_material(true, true, false);

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, reason, .. })
            if key == "runtime_keys"
                && reason.contains("Request Object decryption")
    ));
}

#[test]
fn runtime_allows_shared_oidc_signing_backend_boundary() -> ConfigTestResult {
    let _lock = env_lock();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _oidc_sessions = EnvVarGuard::new(
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        Some("redis://127.0.0.1:6379/0"),
    );
    let cfg = ServerConfig::default();

    must_ok!(
        cfg.validate_runtime_boundaries_with_key_material(true, false, false),
        "shared OIDC signing backend boundary",
    );
    Ok(())
}
