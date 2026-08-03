use super::jwks_fetch::fetch_jwks_with_state;
use super::jwks_validation::select_jwk;
use super::*;
use crate::middleware::{InMemoryReplayStore, ReplayStore, ReplayStoreError};
use crate::test_utils::env_inventory::{
    assert_env_inventory_complete, inventory_map, keys_with_authority, EnvAuthority,
};
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderValue, CACHE_CONTROL};
use std::collections::BTreeSet;
use std::sync::MutexGuard;
use uuid::Uuid;

const TEST_RSA_PUBLIC_KEY_PEM: &str = include_str!("../../../tests/fixtures/rsa2048-public.pem");
const TEST_RSA_PRIVATE_KEY_PEM: &str =
    include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem");
const CLIENT_REGISTRY_ENV_INVENTORY: &[(&str, EnvAuthority)] = &[
    (
        "AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL",
        EnvAuthority::SharedRuntimeStore,
    ),
    (
        "AEGAEON_CLIENT_JWT_ALLOWED_ALGS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_CLIENT_JWT_REQUIRE_KID",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    ("AEGAEON_DPOP_REDIS_URL", EnvAuthority::SharedRuntimeStore),
    (
        "AEGAEON_JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS",
        EnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_JWKS_ALLOW_KID_REUSE",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_CACHE_TTL_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    ("AEGAEON_JWKS_CA_BUNDLE", EnvAuthority::SystemBootstrap),
    (
        "AEGAEON_JWKS_CIRCUIT_OPEN_FAILS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_CIRCUIT_RESET_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_HISTOGRAM_BUCKETS",
        EnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_JWKS_HTTP_RETRIES",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_HTTP_TIMEOUT_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_INSECURE_SKIP_VERIFY",
        EnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_JWKS_LOG_SAMPLE_PERCENT",
        EnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_{outcome}",
        EnvAuthority::SystemBootstrap,
    ),
    (
        "AEGAEON_JWKS_MAX_BODY_BYTES",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    ("AEGAEON_JWKS_REDIS_URL", EnvAuthority::SharedRuntimeStore),
    (
        "AEGAEON_JWKS_REFRESH_SKEW_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_REQUIRE_PIN_ON_STALE",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_SHARED_CACHE_GC_INTERVAL_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_SHARED_CACHE_MAX_AGE_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_SHARED_CACHE_PATH",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_STALE_IF_ERROR_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_STALE_MAX_GENERATIONS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_STALE_MEMORY_MAX_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_STALE_PREFERENCE",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWKS_STALE_SHARED_MAX_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_JWT_BEARER_JTI_WINDOW_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
    (
        "AEGAEON_PKJWT_JTI_WINDOW_SECS",
        EnvAuthority::RemovedRuntimePolicy,
    ),
];

type TestResult = Result<(), String>;

fn test_context<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> Result<T, String> {
    result.map_err(|error| format!("{context}: {error:?}"))
}

fn test_err<T, E>(result: Result<T, E>, context: &str) -> Result<E, String> {
    result.err().ok_or_else(|| context.to_string())
}

fn test_some<T>(value: Option<T>, context: &str) -> Result<T, String> {
    value.ok_or_else(|| context.to_string())
}

fn test_lock<'a, T>(
    result: std::sync::LockResult<MutexGuard<'a, T>>,
    context: &str,
) -> Result<MutexGuard<'a, T>, String> {
    result.map_err(|_| context.to_string())
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var_os(key);
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn env_lock() -> Result<MutexGuard<'static, ()>, String> {
    test_lock(
        crate::util::SERVER_TEST_ENV_GUARD.lock(),
        "JWKS env guard should not be poisoned",
    )
}

#[test]
fn client_registry_env_literals_are_classified() {
    assert_env_inventory_complete(
        concat!(
            include_str!("../../client_registry.rs"),
            include_str!("../client_assertion_policy.rs"),
            include_str!("mod.rs"),
            include_str!("registry_env.rs"),
            include_str!("redis_runtime.rs"),
            include_str!("runtime_policy.rs"),
            include_str!("registry_core.rs"),
        ),
        CLIENT_REGISTRY_ENV_INVENTORY,
        &["AEGAEON_TEST_"],
        &[],
    );
}

#[test]
fn client_registry_removed_runtime_policy_env_keys_are_explicit() {
    assert_eq!(
        keys_with_authority(
            CLIENT_REGISTRY_ENV_INVENTORY,
            EnvAuthority::RemovedRuntimePolicy,
        ),
        BTreeSet::from([
            "AEGAEON_CLIENT_JWT_ALLOWED_ALGS",
            "AEGAEON_CLIENT_JWT_REQUIRE_KID",
            "AEGAEON_JWKS_ALLOW_KID_REUSE",
            "AEGAEON_JWKS_CACHE_TTL_SECS",
            "AEGAEON_JWKS_CIRCUIT_OPEN_FAILS",
            "AEGAEON_JWKS_CIRCUIT_RESET_SECS",
            "AEGAEON_JWKS_HTTP_RETRIES",
            "AEGAEON_JWKS_HTTP_TIMEOUT_SECS",
            "AEGAEON_JWKS_MAX_BODY_BYTES",
            "AEGAEON_JWKS_REFRESH_SKEW_SECS",
            "AEGAEON_JWKS_REQUIRE_PIN_ON_STALE",
            "AEGAEON_JWKS_SHARED_CACHE_GC_INTERVAL_SECS",
            "AEGAEON_JWKS_SHARED_CACHE_MAX_AGE_SECS",
            "AEGAEON_JWKS_SHARED_CACHE_PATH",
            "AEGAEON_JWKS_STALE_IF_ERROR_SECS",
            "AEGAEON_JWKS_STALE_MAX_GENERATIONS",
            "AEGAEON_JWKS_STALE_MEMORY_MAX_SECS",
            "AEGAEON_JWKS_STALE_PREFERENCE",
            "AEGAEON_JWKS_STALE_SHARED_MAX_SECS",
            "AEGAEON_JWT_BEARER_JTI_WINDOW_SECS",
            "AEGAEON_PKJWT_JTI_WINDOW_SECS",
        ])
    );
    assert!(
        !inventory_map(CLIENT_REGISTRY_ENV_INVENTORY)["AEGAEON_CLIENT_JWT_ALLOWED_ALGS"]
            .is_allowed_with_management_database()
    );
}

mod registry_core;
mod runtime_policy;

mod jwks_circuit_tests;
mod jwks_validation_tests;

mod redis_runtime;
mod registry_env;
