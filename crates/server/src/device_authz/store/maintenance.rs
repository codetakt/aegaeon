use super::{log_device_code_storage_error, DeviceCodeStore, DeviceCodeStoreBackend};
use crate::device_authz::redis_backend::now_unix_millis;
#[cfg(test)]
use crate::device_authz::types::DeviceCodeEntry;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::RwLock;

impl DeviceCodeStore {
    /// Clean up expired entries.
    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            DeviceCodeStoreBackend::InMemory(backend) => {
                backend.cleanup_expired();
                Ok(())
            }
            DeviceCodeStoreBackend::Redis(backend) => backend
                .cleanup_expired(now_unix_millis())
                .map_err(|err| err.to_string()),
        }
    }

    /// Clean up expired entries.
    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test device authorization cleanup should succeed");
    }

    /// Get the count of active device codes (for monitoring).
    #[must_use]
    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.try_active_count()
            .expect("test device authorization active count should succeed")
    }

    /// Get the count of active device codes, reporting backend failures.
    pub fn try_active_count(&self) -> Result<usize, String> {
        match &self.backend {
            #[cfg(test)]
            DeviceCodeStoreBackend::InMemory(backend) => backend.try_active_count(),
            DeviceCodeStoreBackend::Redis(backend) => {
                backend.active_count(now_unix_millis()).map_err(|err| {
                    let message = err.to_string();
                    log_device_code_storage_error(&err, "active_count");
                    message
                })
            }
        }
    }

    #[cfg(test)]
    pub(in crate::device_authz) fn in_memory_by_hash(
        &self,
    ) -> Result<&RwLock<HashMap<String, DeviceCodeEntry>>, String> {
        match &self.backend {
            DeviceCodeStoreBackend::InMemory(backend) => Ok(backend.by_hash()),
            DeviceCodeStoreBackend::Redis(_) => {
                Err("expected in-memory device code store".to_string())
            }
        }
    }
}
