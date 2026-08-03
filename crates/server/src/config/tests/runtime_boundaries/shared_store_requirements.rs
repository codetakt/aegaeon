use super::*;

#[test]
fn runtime_requires_shared_device_store_even_when_device_flow_is_disabled() {
    let _lock = env_lock();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _missing_device_code_store = EnvVarGuard::new("AEGAEON_DEVICE_CODE_REDIS_URL", None);
    let cfg = ServerConfig {
        enable_device_authz: false,
        ..ServerConfig::default()
    };

    let result = cfg.validate_runtime_boundaries_with_key_material(false, false, false);

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, reason, .. })
            if key == "shared_runtime_stores"
                && reason.contains("device-code store")
                && reason.contains("AEGAEON_DEVICE_CODE_REDIS_URL")
    ));
}

#[test]
fn runtime_requires_shared_dpop_replay_store_even_when_dpop_is_disabled() {
    let _lock = env_lock();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _missing_dpop_replay_store = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let base = ServerConfig::default();
    let cfg = ServerConfig {
        dpop_strict: false,
        require_dpop_nonce: false,
        security_policy: base
        .security_policy
            .with_sender_constraint(SenderConstraint::None),
        ..base
    };

    let result = cfg.validate_runtime_boundaries_with_key_material(false, false, false);

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, reason, .. })
            if key == "shared_runtime_stores"
                && reason.contains("DPoP replay store")
                && reason.contains("AEGAEON_DPOP_REDIS_URL")
    ));
}

#[test]
fn runtime_requires_shared_jwks_runtime_state_for_supported_runtime() {
    let _lock = env_lock();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _missing_jwks_runtime_state = EnvVarGuard::new("AEGAEON_JWKS_REDIS_URL", None);
    let cfg = ServerConfig::default();

    let result = cfg.validate_runtime_boundaries_with_key_material(false, false, false);

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, reason, .. })
            if key == "shared_runtime_stores"
                && reason.contains("JWKS runtime state")
                && reason.contains("AEGAEON_JWKS_REDIS_URL")
    ));
}

#[test]
fn runtime_accepts_shared_jwks_runtime_state_for_supported_runtime() -> ConfigTestResult {
    let _lock = env_lock();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let cfg = ServerConfig::default();

    must_ok!(
        cfg.validate_runtime_boundaries_with_key_material(false, false, false),
        "shared JWKS runtime-state preflight",
    );

    Ok(())
}

#[test]
fn runtime_requires_shared_stores() {
    let _lock = env_lock();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let cfg = ServerConfig::default();

    let result = cfg.validate_runtime_boundaries_with_key_material(false, false, false);

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, reason, .. })
            if key == "shared_runtime_stores"
                && reason.contains("DB/Redis-backed stores")
                && reason.contains("competing runtime state")
                && reason.contains("AEGAEON_PAR_REDIS_URL")
    ));
}
