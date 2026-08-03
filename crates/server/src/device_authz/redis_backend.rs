use super::{DevicePollResult, DeviceUserCodeLookup, SLOW_DOWN_INCREMENT_SECS};
use crate::config::RuntimeStateNamespace;
use aegaeon_crypto::hash::Sha256Hasher;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[cfg(test)]
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod codec;
mod keyspace;
mod model;
mod reply;
mod scripts;

pub(super) use model::{DeviceCodeStorageError, RedisDeviceCodeEntry};

#[cfg(test)]
pub(super) use keyspace::RedisDeviceCodeKeyspace;
#[cfg(not(test))]
use keyspace::RedisDeviceCodeKeyspace;
use reply::{redis_poll_result, redis_user_code_lookup_result};

pub(super) const DEVICE_CODE_REDIS_URL_ENV: &str = "AEGAEON_DEVICE_CODE_REDIS_URL";

#[derive(Clone)]
pub(super) struct RedisDeviceCodeStoreBackend {
    client: redis::Client,
    keyspace: RedisDeviceCodeKeyspace,
}

pub(super) fn system_time_millis(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| duration.as_millis().try_into().ok())
}

pub(super) fn now_unix_millis() -> u64 {
    system_time_millis(SystemTime::now()).unwrap_or(u64::MAX)
}

pub(super) fn redis_user_code_lookup_key(normalized_user_code: &str) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(b"aegaeon:device-code:user-code:v1");
    hasher.update(&(normalized_user_code.len() as u64).to_be_bytes());
    hasher.update(normalized_user_code.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

impl RedisDeviceCodeStoreBackend {
    pub(super) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, DeviceCodeStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                keyspace: RedisDeviceCodeKeyspace::from_runtime_namespace(namespace),
            })
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(super) fn new_with_prefix(
        url: &str,
        prefix: impl Into<Arc<str>>,
    ) -> Result<Self, DeviceCodeStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                keyspace: RedisDeviceCodeKeyspace::from_test_prefix(prefix),
            })
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, DeviceCodeStorageError> {
        self.client
            .get_connection()
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn insert_entry(
        &self,
        device_code_hash: &str,
        user_code_lookup_key: &str,
        entry: &RedisDeviceCodeEntry,
        now_ms: u64,
    ) -> Result<bool, DeviceCodeStorageError> {
        let retention_ms = codec::retention_millis(entry.expires_at_ms, now_ms)?;
        let (status, approved_user_id) = codec::status_fields(&entry.status);
        let mut conn = self.connection()?;
        redis::Script::new(scripts::INSERT_ENTRY)
            .key(self.keyspace.entry_key(device_code_hash))
            .key(self.keyspace.user_code_key(user_code_lookup_key))
            .key(self.keyspace.expiries_key())
            .arg(device_code_hash)
            .arg(user_code_lookup_key)
            .arg(&entry.client_id)
            .arg(codec::option_present(entry.scope.as_deref()))
            .arg(codec::option_value(entry.scope.as_deref()))
            .arg(codec::option_present(entry.resource.as_deref()))
            .arg(codec::option_value(entry.resource.as_deref()))
            .arg(codec::option_present(entry.environment_id.as_deref()))
            .arg(codec::option_value(entry.environment_id.as_deref()))
            .arg(status)
            .arg(approved_user_id)
            .arg(entry.expires_at_ms)
            .arg(retention_ms)
            .arg(entry.poll_interval_secs)
            .arg(now_ms)
            .arg(self.keyspace.entry_key_prefix())
            .arg(self.keyspace.user_code_key_prefix())
            .invoke::<i64>(&mut conn)
            .map(|value| value == 1)
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn poll(
        &self,
        hash: &str,
        client_id: &str,
        environment_id: Option<&str>,
        requested_resource: Option<&str>,
        now_ms: u64,
    ) -> Result<DevicePollResult, DeviceCodeStorageError> {
        let mut conn = self.connection()?;
        let reply = redis::Script::new(scripts::POLL)
            .key(self.keyspace.entry_key(hash))
            .key(self.keyspace.expiries_key())
            .arg(client_id)
            .arg(if environment_id.is_some() { "1" } else { "0" })
            .arg(environment_id.unwrap_or(""))
            .arg(if requested_resource.is_some() {
                "1"
            } else {
                "0"
            })
            .arg(requested_resource.unwrap_or(""))
            .arg(now_ms)
            .arg(SLOW_DOWN_INCREMENT_SECS)
            .arg(hash)
            .arg(self.keyspace.entry_key_prefix())
            .arg(self.keyspace.user_code_key_prefix())
            .invoke::<Vec<String>>(&mut conn)
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))?;
        Ok(redis_poll_result(&reply))
    }

    pub(super) fn approve(
        &self,
        normalized_user_code: &str,
        user_id: &str,
        now_ms: u64,
    ) -> Result<bool, DeviceCodeStorageError> {
        self.transition_user_code(normalized_user_code, now_ms, "approved", user_id)
    }

    pub(super) fn deny(
        &self,
        normalized_user_code: &str,
        now_ms: u64,
    ) -> Result<bool, DeviceCodeStorageError> {
        self.transition_user_code(normalized_user_code, now_ms, "denied", "")
    }

    fn transition_user_code(
        &self,
        normalized_user_code: &str,
        now_ms: u64,
        next_status: &str,
        approved_user_id: &str,
    ) -> Result<bool, DeviceCodeStorageError> {
        let lookup = redis_user_code_lookup_key(normalized_user_code);
        let mut conn = self.connection()?;
        redis::Script::new(scripts::TRANSITION_USER_CODE)
            .key(self.keyspace.user_code_key(&lookup))
            .key(self.keyspace.expiries_key())
            .arg(now_ms)
            .arg(next_status)
            .arg(approved_user_id)
            .arg(self.keyspace.entry_key_prefix())
            .invoke::<i64>(&mut conn)
            .map(|value| value == 1)
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn lookup_by_user_code(
        &self,
        normalized_user_code: &str,
        now_ms: u64,
    ) -> Result<Option<DeviceUserCodeLookup>, DeviceCodeStorageError> {
        let lookup = redis_user_code_lookup_key(normalized_user_code);
        let mut conn = self.connection()?;
        let reply = redis::Script::new(scripts::LOOKUP_BY_USER_CODE)
            .key(self.keyspace.user_code_key(&lookup))
            .key(self.keyspace.expiries_key())
            .arg(now_ms)
            .arg(self.keyspace.entry_key_prefix())
            .invoke::<Option<Vec<String>>>(&mut conn)
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))?;
        Ok(reply.as_deref().and_then(redis_user_code_lookup_result))
    }

    pub(super) fn cleanup_expired(&self, now_ms: u64) -> Result<(), DeviceCodeStorageError> {
        let mut conn = self.connection()?;
        redis::Script::new(scripts::CLEANUP_EXPIRED)
            .key(self.keyspace.expiries_key())
            .arg(now_ms)
            .arg(self.keyspace.entry_key_prefix())
            .arg(self.keyspace.user_code_key_prefix())
            .invoke::<i64>(&mut conn)
            .map(|_| ())
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn active_count(&self, now_ms: u64) -> Result<usize, DeviceCodeStorageError> {
        self.cleanup_expired(now_ms)?;
        let mut conn = self.connection()?;
        redis::cmd("ZCOUNT")
            .arg(self.keyspace.expiries_key())
            .arg(format!("({now_ms}"))
            .arg("+inf")
            .query::<usize>(&mut conn)
            .map_err(|err| DeviceCodeStorageError::BackendUnavailable(err.to_string()))
    }
}
