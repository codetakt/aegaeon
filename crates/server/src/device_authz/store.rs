use super::redis_backend::{DeviceCodeStorageError, RedisDeviceCodeStoreBackend};
use super::DeviceAuthorizationResponse;
use std::time::Duration;

mod creation;
#[cfg(test)]
mod in_memory;
mod maintenance;
mod operations;
mod runtime;

#[cfg(test)]
use in_memory::{InMemoryDeviceCodeStore, InMemoryInsertResult};

/// Thread-safe store for device authorization codes.
#[derive(Clone)]
pub struct DeviceCodeStore {
    pub(super) backend: DeviceCodeStoreBackend,
    /// Device code TTL.
    pub(super) ttl: Duration,
    /// Default poll interval.
    pub(super) default_interval_secs: u64,
}

#[derive(Clone)]
pub(super) enum DeviceCodeStoreBackend {
    #[cfg(test)]
    InMemory(InMemoryDeviceCodeStore),
    Redis(RedisDeviceCodeStoreBackend),
}

pub(super) enum DeviceCodeCreateResult {
    Created(DeviceAuthorizationResponse),
    Collision,
    Unavailable,
}

fn log_device_code_storage_error(error: &DeviceCodeStorageError, operation: &str) {
    tracing::error!(error = %error, operation, "device code store operation failed");
}
