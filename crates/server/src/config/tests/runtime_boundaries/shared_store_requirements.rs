use super::*;

#[test]
fn native_runtime_store_inventory_has_no_redis_domains() {
    let _lock = env_lock();
    let _cleared = clear_shared_runtime_store_env();
    let config = maximal_shared_runtime_store_config();
    assert!(config
        .shared_runtime_store_requirements(true)
        .unwrap()
        .is_empty());
    let _legacy = EnvVarGuard::new(
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        Some("rediss://private:must-not-log@other.example/9"),
    );
    assert!(config.validate_shared_runtime_store_preflight(true).is_ok());
}

#[test]
fn native_device_store_does_not_require_redis_for_either_flow_setting() {
    let _lock = env_lock();
    let _cleared = clear_shared_runtime_store_env();
    for enabled in [false, true] {
        let cfg = ServerConfig {
            enable_device_authz: enabled,
            ..ServerConfig::default()
        };
        assert!(cfg.validate_shared_runtime_store_preflight(false).is_ok());
    }
}

#[test]
fn runtime_replay_decisions_do_not_require_redis() {
    let _lock = env_lock();
    let _stores = set_base_shared_runtime_store_env();
    let _dpop = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let _assertions = EnvVarGuard::new("AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL", None);
    assert!(maximal_shared_runtime_store_config()
        .validate_shared_runtime_store_preflight(true)
        .is_ok());
}

#[test]
fn runtime_jwks_does_not_require_redis() {
    let _lock = env_lock();
    let _optional_surfaces = clear_optional_shared_runtime_surfaces();
    let _cleared_shared_stores = clear_shared_runtime_store_env();
    let _shared_stores = set_base_shared_runtime_store_env();
    let _missing_jwks_runtime_state = EnvVarGuard::new("AEGAEON_JWKS_REDIS_URL", None);
    assert!(ServerConfig::default()
        .validate_shared_runtime_store_preflight(false)
        .is_ok());
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
fn native_runtime_stores_do_not_require_redis() {
    let _lock = env_lock();
    let _optional = clear_optional_shared_runtime_surfaces();
    let _cleared = clear_shared_runtime_store_env();
    assert!(maximal_shared_runtime_store_config()
        .validate_shared_runtime_store_preflight(true)
        .is_ok());
}

#[test]
fn runtime_security_budgets_do_not_require_redis() {
    let _lock = env_lock();
    let _stores = set_base_shared_runtime_store_env();
    let _device = EnvVarGuard::new("AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL", None);
    let _local = EnvVarGuard::new("AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL", None);
    let _management = EnvVarGuard::new("AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL", None);
    assert!(maximal_shared_runtime_store_config()
        .validate_shared_runtime_store_preflight(true)
        .is_ok());
}
