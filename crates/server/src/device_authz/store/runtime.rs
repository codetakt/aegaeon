#[cfg(test)]
use super::InMemoryDeviceCodeStore;
use super::{DeviceCodeStore, DeviceCodeStoreBackend};
#[cfg(test)]
use crate::config::DEFAULT_DEVICE_CODE_TTL_SECS;
use crate::config::{
    require_shared_runtime_store_url, ConfigError, RuntimeStateNamespace,
    DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS, MAX_DEVICE_CODE_POLL_INTERVAL_SECS,
    MAX_DEVICE_CODE_TTL_SECS,
};
use crate::device_authz::redis_backend::{RedisDeviceCodeStoreBackend, DEVICE_CODE_REDIS_URL_ENV};
use std::time::Duration;

impl DeviceCodeStore {
    #[cfg(test)]
    fn new_process_local(ttl: Duration, default_interval_secs: u64) -> Self {
        Self {
            backend: DeviceCodeStoreBackend::InMemory(InMemoryDeviceCodeStore::new()),
            ttl,
            default_interval_secs,
        }
    }

    /// Create a process-local device-code store for tests.
    ///
    /// Production code should use [`Self::try_from_shared_store_env`] so shared runtime state is
    /// required.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local(
            Duration::from_secs(DEFAULT_DEVICE_CODE_TTL_SECS),
            DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS,
        )
    }

    pub fn try_from_shared_store_env_with_policy(
        ttl_secs: u64,
        default_interval_secs: u64,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        validate_device_code_runtime_policy(ttl_secs, default_interval_secs)?;
        let url = require_shared_runtime_store_url("device-code store", DEVICE_CODE_REDIS_URL_ENV)?;
        let backend = RedisDeviceCodeStoreBackend::new(url.as_str(), runtime_state_namespace)
            .map_err(|err| ConfigError::InvalidValue {
                key: url.env_key().to_string(),
                value: "[redacted]".to_string(),
                reason: err.to_string(),
            })?;
        tracing::info!("device code store backend: redis");
        Ok(Self {
            backend: DeviceCodeStoreBackend::Redis(backend),
            ttl: Duration::from_secs(ttl_secs),
            default_interval_secs,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(in crate::device_authz) fn new_process_local_with_ttl_for_tests(ttl_secs: u64) -> Self {
        Self::new_process_local(
            Duration::from_secs(ttl_secs),
            DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS,
        )
    }

    /// Create a store with custom TTL and poll interval (for testing).
    #[cfg(test)]
    pub(in crate::device_authz) fn new_process_local_with_ttl_and_interval_for_tests(
        ttl_secs: u64,
        interval_secs: u64,
    ) -> Self {
        Self::new_process_local(Duration::from_secs(ttl_secs), interval_secs)
    }
}

fn validate_device_code_runtime_policy(
    ttl_secs: u64,
    default_interval_secs: u64,
) -> Result<(), ConfigError> {
    if !crate::config::valid_device_code_ttl_secs(ttl_secs) {
        return Err(ConfigError::InvalidNumberRange {
            key: "device_code_ttl_seconds".to_string(),
            value: ttl_secs.to_string(),
            expectation: format!("a value in 1..={MAX_DEVICE_CODE_TTL_SECS} seconds"),
        });
    }
    if !crate::config::valid_device_code_poll_interval_secs(default_interval_secs) {
        return Err(ConfigError::InvalidNumberRange {
            key: "device_code_poll_interval_seconds".to_string(),
            value: default_interval_secs.to_string(),
            expectation: format!(
                "a value in {DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS}..={MAX_DEVICE_CODE_POLL_INTERVAL_SECS} seconds"
            ),
        });
    }
    Ok(())
}
