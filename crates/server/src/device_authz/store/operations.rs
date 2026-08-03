use super::{log_device_code_storage_error, DeviceCodeStore, DeviceCodeStoreBackend};
use crate::device_authz::codes::{hash_device_code, normalize_user_code};
use crate::device_authz::redis_backend::now_unix_millis;
use crate::device_authz::{DevicePollResult, DeviceUserCodeLookup};

impl DeviceCodeStore {
    /// Poll for device code status, reporting backend failures.
    ///
    /// Enforces rate limiting (DA-1) and single-use semantics (DA-5).
    /// The `environment_id` parameter enforces DA-7 (environment scoping).
    /// The `requested_resource` parameter enforces RFC 8707 binding to the
    /// resource value captured on the device authorization request.
    pub fn try_poll(
        &self,
        device_code: &str,
        client_id: &str,
        environment_id: Option<&str>,
        requested_resource: Option<&str>,
    ) -> Result<DevicePollResult, String> {
        let hash = hash_device_code(device_code);
        match &self.backend {
            #[cfg(test)]
            DeviceCodeStoreBackend::InMemory(backend) => {
                Ok(backend.poll(&hash, client_id, environment_id, requested_resource))
            }
            DeviceCodeStoreBackend::Redis(backend) => backend
                .poll(
                    &hash,
                    client_id,
                    environment_id,
                    requested_resource,
                    now_unix_millis(),
                )
                .map_err(|err| {
                    let message = err.to_string();
                    log_device_code_storage_error(&err, "poll");
                    message
                }),
        }
    }

    /// Poll for device code status on the blocking worker pool.
    pub async fn try_poll_async(
        &self,
        device_code: String,
        client_id: String,
        environment_id: Option<String>,
        requested_resource: Option<String>,
    ) -> Result<DevicePollResult, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.try_poll(
                &device_code,
                &client_id,
                environment_id.as_deref(),
                requested_resource.as_deref(),
            )
        })
        .await
        .map_err(|err| format!("device code store worker failed: {err}"))?
    }

    /// Approve a device authorization by user code, reporting backend failures.
    pub fn try_approve(&self, user_code: &str, user_id: &str) -> Result<bool, String> {
        let normalized = normalize_user_code(user_code);
        match &self.backend {
            #[cfg(test)]
            DeviceCodeStoreBackend::InMemory(backend) => backend.approve(&normalized, user_id),
            DeviceCodeStoreBackend::Redis(backend) => backend
                .approve(&normalized, user_id, now_unix_millis())
                .map_err(|err| {
                    let message = err.to_string();
                    log_device_code_storage_error(&err, "approve");
                    message
                }),
        }
    }

    /// Approve a device authorization by user code on the blocking worker pool.
    pub async fn try_approve_async(
        &self,
        user_code: String,
        user_id: String,
    ) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_approve(&user_code, &user_id))
            .await
            .map_err(|err| format!("device code store worker failed: {err}"))?
    }

    /// Deny a device authorization by user code, reporting backend failures.
    pub fn try_deny(&self, user_code: &str) -> Result<bool, String> {
        let normalized = normalize_user_code(user_code);
        match &self.backend {
            #[cfg(test)]
            DeviceCodeStoreBackend::InMemory(backend) => backend.deny(&normalized),
            DeviceCodeStoreBackend::Redis(backend) => {
                backend.deny(&normalized, now_unix_millis()).map_err(|err| {
                    let message = err.to_string();
                    log_device_code_storage_error(&err, "deny");
                    message
                })
            }
        }
    }

    /// Deny a device authorization by user code on the blocking worker pool.
    pub async fn try_deny_async(&self, user_code: String) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_deny(&user_code))
            .await
            .map_err(|err| format!("device code store worker failed: {err}"))?
    }

    /// Look up a pending device authorization by user code, reporting backend failures.
    pub fn try_lookup_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceUserCodeLookup>, String> {
        let normalized = normalize_user_code(user_code);
        match &self.backend {
            #[cfg(test)]
            DeviceCodeStoreBackend::InMemory(backend) => backend.lookup_by_user_code(&normalized),
            DeviceCodeStoreBackend::Redis(backend) => {
                match backend.lookup_by_user_code(&normalized, now_unix_millis()) {
                    Ok(result) => Ok(result),
                    Err(err) => {
                        let message = err.to_string();
                        log_device_code_storage_error(&err, "lookup_by_user_code");
                        Err(message)
                    }
                }
            }
        }
    }

    /// Look up a pending device authorization by user code on the blocking worker pool.
    pub async fn try_lookup_by_user_code_async(
        &self,
        user_code: String,
    ) -> Result<Option<DeviceUserCodeLookup>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_lookup_by_user_code(&user_code))
            .await
            .map_err(|err| format!("device code store worker failed: {err}"))?
    }
}
