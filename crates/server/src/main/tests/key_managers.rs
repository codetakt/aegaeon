use super::*;
use aegaeon_server::runtime_keys::RuntimeKeySet;

const TEST_DATABASE_URL: &str = "postgres://aegaeon:test@127.0.0.1/aegaeon_test";
const TEST_REDIS_URL: &str = "redis://127.0.0.1:6379/0";

fn set_base_shared_runtime_store_env() -> Vec<EnvVarGuard> {
    [
        "AEGAEON_AUTH_CODE_REDIS_URL",
        "AEGAEON_AUTH_SESSION_REDIS_URL",
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        "AEGAEON_DEVICE_CODE_REDIS_URL",
        "AEGAEON_DEVICE_CSRF_REDIS_URL",
        "AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL",
        "AEGAEON_DPOP_NONCE_REDIS_URL",
        "AEGAEON_DPOP_REDIS_URL",
        "AEGAEON_JWKS_REDIS_URL",
        "AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL",
        "AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL",
        "AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL",
        "AEGAEON_MANAGEMENT_SESSION_REDIS_URL",
        "AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL",
        "AEGAEON_PAR_REDIS_URL",
        "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        "AEGAEON_STEPUP_REDIS_URL",
        "AEGAEON_TOKEN_STORE_REDIS_URL",
        "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
        "AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL",
    ]
    .into_iter()
    .map(|key| EnvVarGuard::new(key, Some(TEST_REDIS_URL)))
    .collect()
}

#[test]
fn disabled_key_manager_fails_closed_without_runtime_key_material() {
    let manager = DisabledKeyManager;

    assert!(matches!(
        manager.sign(b"message"),
        Err(KeyManagerError::KeyNotFound)
    ));
    assert!(matches!(
        manager.verify(b"message", b"signature"),
        Err(KeyManagerError::KeyNotFound)
    ));
    assert!(manager.jwt_signing_public_jwk().is_none());
}

#[test]
fn disabled_key_managers_are_used_for_disabled_runtime_surfaces() -> TestResult {
    let _lock = env_lock()?;
    let _database_url = EnvVarGuard::new("AEGAEON_DATABASE_URL", Some(TEST_DATABASE_URL));
    let _shared_runtime_stores = set_base_shared_runtime_store_env();
    let cfg = BootstrapConfig::try_from_env()?.into_runtime_baseline();
    let runtime_keys = RuntimeKeySet::default();

    let (key_manager, introspection_key_manager) = runtime_key_managers(&cfg, &runtime_keys)?;
    assert!(introspection_key_manager.is_none());
    assert!(matches!(
        key_manager.sign(b"message"),
        Err(KeyManagerError::KeyNotFound)
    ));
    Ok(())
}
