use super::*;
use crate::config::ConfigError;
use crate::middleware::{ReplayEntry, ReplayStore, ReplayStoreError};
use std::thread;

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var(key).ok();
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

struct UnavailableReplayStore;

impl ReplayStore for UnavailableReplayStore {
    fn check_and_store(&self, _entry: ReplayEntry<'_>) -> Result<(), ReplayStoreError> {
        Err(ReplayStoreError::BackendUnavailable(
            "test backend".to_string(),
        ))
    }
}

#[test]
fn rejects_replay_within_ttl() {
    let store = RequestObjectJtiStore::new_process_local_for_tests(Duration::from_secs(10));
    assert!(store.check_and_store("client", "jti-1").is_ok());
    let err = store.check_and_store("client", "jti-1");
    assert_eq!(err, Err(RequestObjectReplayError::Replay));
}

#[test]
fn allows_reuse_after_ttl_expires() {
    let store = RequestObjectJtiStore::new_process_local_for_tests(Duration::from_millis(20));
    assert!(store.check_and_store("client", "jti-2").is_ok());
    thread::sleep(Duration::from_millis(30));
    assert!(store.check_and_store("client", "jti-2").is_ok());
}

#[test]
fn isolates_jti_per_client() {
    let store = RequestObjectJtiStore::new_process_local_for_tests(Duration::from_secs(10));
    assert!(store.check_and_store("client-a", "shared-jti").is_ok());
    assert!(store.check_and_store("client-b", "shared-jti").is_ok());
}

#[test]
fn replay_key_is_not_delimiter_ambiguous() {
    let store = RequestObjectJtiStore::new_process_local_for_tests(Duration::from_secs(10));
    assert!(store.check_and_store("client", "jti::suffix").is_ok());
    assert!(store.check_and_store("client::jti", "suffix").is_ok());
}

#[test]
fn backend_unavailable_fails_closed() {
    let store = RequestObjectJtiStore::with_replay_store(
        Duration::from_secs(10),
        Arc::new(UnavailableReplayStore),
    );

    let result = store.check_and_store("client", "jti");

    assert!(matches!(
        result,
        Err(RequestObjectReplayError::BackendUnavailable(_))
    ));
}

#[test]
fn check_and_store_for_uses_entry_retention() {
    let store = RequestObjectJtiStore::new_process_local_for_tests(Duration::from_secs(10));
    assert!(store
        .check_and_store_for("client", "short-jti", Duration::from_millis(20))
        .is_ok());
    thread::sleep(Duration::from_millis(30));
    assert!(store
        .check_and_store_for("client", "short-jti", Duration::from_millis(20))
        .is_ok());
}

#[test]
fn replay_key_material_is_length_delimited() {
    assert_ne!(
        request_object_replay_key_material("client", "jti::suffix"),
        request_object_replay_key_material("client::jti", "suffix")
    );
}

#[test]
fn explicit_request_object_jti_ttl_rejects_unbounded_values() -> Result<(), String> {
    let namespace = crate::config::RuntimeStateNamespace::for_tests("request-object-jti-test");
    let err = RequestObjectJtiStore::try_from_shared_store_env_with_ttl_secs(
        crate::config::MAX_REQUEST_OBJECT_JTI_TTL_SECS + 1,
        &namespace,
    )
    .err()
    .ok_or_else(|| "unbounded request-object jti ttl must fail closed".to_string())?;

    assert!(matches!(
        err,
        ConfigError::InvalidNumberRange { key, .. }
            if key == "request_object_jti_ttl_seconds"
    ));
    Ok(())
}

#[test]
fn invalid_request_object_redis_url_fails_configuration_closed() -> Result<(), String> {
    let _lock = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|err| format!("request object env guard: {err}"))?;
    let _request_url = EnvVarGuard::new(
        "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        Some("not-a-redis-url"),
    );
    let _dpop_url = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let namespace = crate::config::RuntimeStateNamespace::for_tests("request-object-jti-test");

    let result = RequestObjectJtiStore::try_from_shared_store_env_with_ttl_secs(
        crate::config::DEFAULT_REQUEST_OBJECT_JTI_TTL_SECS,
        &namespace,
    );

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, .. })
            if key == "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL"
    ));
    Ok(())
}

#[test]
fn removed_dpop_redis_fallback_is_ignored_for_request_object_jti_store() -> Result<(), String> {
    let _lock = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|err| format!("request object env guard: {err}"))?;
    let _request_url = EnvVarGuard::new("AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL", None);
    let _dpop_url = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", Some("not-a-redis-url"));
    let namespace = crate::config::RuntimeStateNamespace::for_tests("request-object-jti-test");

    let result = RequestObjectJtiStore::try_from_shared_store_env_with_ttl_secs(
        crate::config::DEFAULT_REQUEST_OBJECT_JTI_TTL_SECS,
        &namespace,
    );

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, .. })
            if key == "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL"
    ));
    Ok(())
}

#[test]
fn missing_shared_replay_store_requires_redis_configuration() -> Result<(), String> {
    let _lock = crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|err| format!("request object env guard: {err}"))?;
    let _request_url = EnvVarGuard::new("AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL", None);
    let _dpop_url = EnvVarGuard::new("AEGAEON_DPOP_REDIS_URL", None);
    let namespace = crate::config::RuntimeStateNamespace::for_tests("request-object-jti-test");

    let result = RequestObjectJtiStore::try_from_shared_store_env_with_ttl_secs(
        crate::config::DEFAULT_REQUEST_OBJECT_JTI_TTL_SECS,
        &namespace,
    );

    assert!(matches!(
        result,
        Err(ConfigError::InvalidValue { key, .. })
            if key == "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL"
    ));
    Ok(())
}
