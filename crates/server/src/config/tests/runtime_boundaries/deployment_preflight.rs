use super::*;

#[test]
fn removed_deployment_mode_env_is_rejected() -> ConfigTestResult {
    let _lock = env_lock();
    let _mode = EnvVarGuard::new(DEPLOYMENT_MODE_ENV, Some("multi-node"));

    let err = must_err!(
        RuntimeStateBoundaryConfig::try_from_env(),
        "removed deployment mode selector must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == DEPLOYMENT_MODE_ENV
                && reason.contains("deployment mode selector was removed")
    ));
    Ok(())
}

#[test]
fn runtime_rejects_without_shared_store_preflight_by_default() {
    let _lock = env_lock();
    let _db = required_database_url();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _shared_stores = clear_shared_runtime_store_env();

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == "shared_runtime_stores"
                && reason.contains("shared-store preflight")
                && reason.contains("AEGAEON_PAR_REDIS_URL")
    ));
}

#[test]
fn runtime_accepts_complete_shared_store_preflight_without_override() -> ConfigTestResult {
    let _lock = env_lock();
    let _db = required_database_url();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();

    must_ok!(
        ServerConfig::try_from_env(),
        "complete shared-store preflight",
    );
    Ok(())
}

#[test]
fn runtime_accepts_rediss_shared_store_preflight() -> ConfigTestResult {
    let _lock = env_lock();
    let _db = required_database_url();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _auth_code =
        EnvVarGuard::new("AEGAEON_AUTH_CODE_REDIS_URL", Some("rediss://redis.example/0"));
    let _token_store = EnvVarGuard::new(
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        Some("rediss://redis.example/0"),
    );
    let _par = EnvVarGuard::new("AEGAEON_PAR_REDIS_URL", Some("rediss://redis.example/0"));
    let _request_object_jti = EnvVarGuard::new(
        "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        Some("rediss://redis.example/0"),
    );
    let _oidc_logout = EnvVarGuard::new(
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        Some("rediss://redis.example/0"),
    );

    must_ok!(
        ServerConfig::try_from_env(),
        "rediss shared-store preflight",
    );
    Ok(())
}

#[test]
fn runtime_rejects_non_redis_shared_store_url() {
    let _lock = env_lock();
    let _db = required_database_url();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _invalid = EnvVarGuard::new("AEGAEON_PAR_REDIS_URL", Some("postgres://db.example/state"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, value, reason }))
            if key == "AEGAEON_PAR_REDIS_URL"
                && value == "postgres"
                && reason.contains("scheme must be rediss:// or loopback redis://")
    ));
}

#[test]
fn runtime_rejects_malformed_shared_store_url_without_echoing_secret() {
    let _lock = env_lock();
    let _db = required_database_url();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _invalid = EnvVarGuard::new(
        "AEGAEON_PAR_REDIS_URL",
        Some("redis://:secret with spaces"),
    );

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, value, reason }))
            if key == "AEGAEON_PAR_REDIS_URL"
                && value == "<redacted>"
                && reason.contains("valid rediss:// URL or loopback redis:// URL")
    ));
}

#[test]
fn removed_ephemeral_ack_is_rejected_before_store_preflight() {
    let _lock = env_lock();
    let _db = required_database_url();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _ephemeral = EnvVarGuard::new(REMOVED_EPHEMERAL_RUNTIME_STATE_ENV, Some("1"));

    let result = panic::catch_unwind(ServerConfig::try_from_env);

    assert!(matches!(
        result,
        Ok(Err(ConfigError::InvalidValue { key, reason, .. }))
            if key == REMOVED_EPHEMERAL_RUNTIME_STATE_ENV
                && reason.contains("legacy ephemeral runtime-state acknowledgement was removed")
    ));
}

#[test]
fn runtime_boundary_has_no_process_local_escape_hatch() -> ConfigTestResult {
    let _lock = env_lock();
    let _ephemeral = EnvVarGuard::new(REMOVED_EPHEMERAL_RUNTIME_STATE_ENV, None);

    must_ok!(
        RuntimeStateBoundaryConfig::try_from_env(),
        "runtime state boundary",
    );
    Ok(())
}

#[test]
fn missing_shared_runtime_store_reports_required_primary_env() -> ConfigTestResult {
    let _lock = env_lock();
    let _primary = EnvVarGuard::new("AEGAEON_PAR_REDIS_URL", None);

    let err = must_err!(
        require_shared_runtime_store_url("PAR request_uri store", "AEGAEON_PAR_REDIS_URL"),
        "missing shared runtime store must fail closed",
    );

    assert!(matches!(
        err,
        ConfigError::InvalidValue { key, reason, .. }
            if key == "AEGAEON_PAR_REDIS_URL"
                && reason.contains("PAR request_uri store requires DB/Redis-backed shared runtime state")
    ));
    Ok(())
}
