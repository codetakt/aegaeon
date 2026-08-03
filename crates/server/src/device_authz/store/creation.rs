#[cfg(test)]
use super::InMemoryInsertResult;
use super::{
    log_device_code_storage_error, DeviceCodeCreateResult, DeviceCodeStore, DeviceCodeStoreBackend,
};
use crate::device_authz::codes::{
    format_user_code, generate_device_code, generate_user_code, hash_device_code,
    normalize_user_code, USER_CODE_GENERATION_ATTEMPTS,
};
use crate::device_authz::redis_backend::{
    now_unix_millis, redis_user_code_lookup_key, system_time_millis, RedisDeviceCodeEntry,
};
use crate::device_authz::types::DeviceCodeEntry;
use crate::device_authz::{DeviceAuthorizationResponse, DeviceAuthzStatus};
use std::time::SystemTime;

impl DeviceCodeStore {
    /// Create a new device authorization request.
    ///
    /// Returns the response to send back to the device (containing the raw `device_code`).
    #[must_use]
    pub fn create(
        &self,
        client_id: &str,
        scope: Option<&str>,
        environment_id: Option<&str>,
        verification_uri: &str,
    ) -> DeviceAuthorizationResponse {
        match self.try_create(client_id, scope, environment_id, verification_uri) {
            Some(response) => response,
            None => {
                tracing::error!("device authorization request allocation failed");
                DeviceAuthorizationResponse {
                    device_code: String::new(),
                    user_code: String::new(),
                    verification_uri: verification_uri.to_string(),
                    verification_uri_complete: None,
                    expires_in: 0,
                    interval: self.default_interval_secs,
                }
            }
        }
    }

    /// Try to create a new device authorization request.
    ///
    /// Returns `None` only if fresh random material repeatedly collides with
    /// live store entries. Callers that can render HTTP errors should use this
    /// method and fail closed instead of overwriting existing user-code state.
    #[must_use]
    pub fn try_create(
        &self,
        client_id: &str,
        scope: Option<&str>,
        environment_id: Option<&str>,
        verification_uri: &str,
    ) -> Option<DeviceAuthorizationResponse> {
        self.try_create_with_resource(client_id, scope, None, environment_id, verification_uri)
    }

    /// Try to create a new device authorization request bound to an optional resource.
    ///
    /// Returns `None` only if fresh random material repeatedly collides with
    /// live store entries. Callers that can render HTTP errors should use this
    /// method and fail closed instead of overwriting existing user-code state.
    #[must_use]
    pub fn try_create_with_resource(
        &self,
        client_id: &str,
        scope: Option<&str>,
        resource: Option<&str>,
        environment_id: Option<&str>,
        verification_uri: &str,
    ) -> Option<DeviceAuthorizationResponse> {
        for _ in 0..USER_CODE_GENERATION_ATTEMPTS {
            match self.try_create_once(client_id, scope, resource, environment_id, verification_uri)
            {
                DeviceCodeCreateResult::Created(response) => return Some(response),
                DeviceCodeCreateResult::Collision => {
                    if let Err(err) = self.try_cleanup_expired() {
                        tracing::error!(
                            error = %err,
                            "device code store cleanup failed after allocation collision"
                        );
                        return None;
                    }
                }
                DeviceCodeCreateResult::Unavailable => return None,
            }
        }
        None
    }

    /// Try to create a new device authorization request on the blocking worker pool.
    pub async fn try_create_with_resource_async(
        &self,
        client_id: String,
        scope: Option<String>,
        resource: Option<String>,
        environment_id: Option<String>,
        verification_uri: String,
    ) -> Option<DeviceAuthorizationResponse> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.try_create_with_resource(
                &client_id,
                scope.as_deref(),
                resource.as_deref(),
                environment_id.as_deref(),
                &verification_uri,
            )
        })
        .await
        .unwrap_or_else(|err| {
            tracing::error!(error = %err, "device code store worker failed during allocation");
            None
        })
    }

    fn try_create_once(
        &self,
        client_id: &str,
        scope: Option<&str>,
        resource: Option<&str>,
        environment_id: Option<&str>,
        verification_uri: &str,
    ) -> DeviceCodeCreateResult {
        let device_code = match generate_device_code() {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(error = %err, "device code generation failed");
                return DeviceCodeCreateResult::Unavailable;
            }
        };
        let user_code = match generate_user_code() {
            Ok(value) => value,
            Err(err) => {
                tracing::error!(error = %err, "user code generation failed");
                return DeviceCodeCreateResult::Unavailable;
            }
        };
        let device_code_hash = hash_device_code(&device_code);
        let Some(expires_at) = SystemTime::now().checked_add(self.ttl) else {
            return DeviceCodeCreateResult::Unavailable;
        };

        let entry = DeviceCodeEntry {
            #[cfg(test)]
            user_code: user_code.clone(),
            client_id: client_id.to_string(),
            scope: scope.map(std::string::ToString::to_string),
            resource: resource.map(std::string::ToString::to_string),
            environment_id: environment_id.map(std::string::ToString::to_string),
            status: DeviceAuthzStatus::Pending,
            expires_at,
            #[cfg(test)]
            last_poll_at: None,
            poll_interval_secs: self.default_interval_secs,
            consumed: false,
        };

        self.try_insert_entry(
            device_code,
            &device_code_hash,
            &user_code,
            entry,
            verification_uri,
        )
    }

    pub(in crate::device_authz) fn try_insert_entry(
        &self,
        device_code: String,
        device_code_hash: &str,
        user_code: &str,
        entry: DeviceCodeEntry,
        verification_uri: &str,
    ) -> DeviceCodeCreateResult {
        let normalized_user_code = normalize_user_code(user_code);
        match &self.backend {
            #[cfg(test)]
            DeviceCodeStoreBackend::InMemory(backend) => {
                match backend.insert_entry(device_code_hash, &normalized_user_code, entry) {
                    InMemoryInsertResult::Inserted => {}
                    InMemoryInsertResult::Collision => return DeviceCodeCreateResult::Collision,
                    InMemoryInsertResult::Unavailable => {
                        return DeviceCodeCreateResult::Unavailable
                    }
                }
            }
            DeviceCodeStoreBackend::Redis(backend) => {
                let Some(expires_at_ms) = system_time_millis(entry.expires_at) else {
                    return DeviceCodeCreateResult::Unavailable;
                };
                let user_code_lookup_key = redis_user_code_lookup_key(&normalized_user_code);
                let redis_entry = RedisDeviceCodeEntry {
                    device_code_hash: device_code_hash.to_string(),
                    user_code_lookup_key: user_code_lookup_key.clone(),
                    client_id: entry.client_id,
                    scope: entry.scope,
                    resource: entry.resource,
                    environment_id: entry.environment_id,
                    status: entry.status,
                    expires_at_ms,
                    last_poll_at_ms: None,
                    poll_interval_secs: entry.poll_interval_secs,
                    consumed: entry.consumed,
                };
                let inserted = backend
                    .insert_entry(
                        device_code_hash,
                        &user_code_lookup_key,
                        &redis_entry,
                        now_unix_millis(),
                    )
                    .map_err(|err| log_device_code_storage_error(&err, "create"))
                    .ok();
                let Some(inserted) = inserted else {
                    return DeviceCodeCreateResult::Unavailable;
                };
                if !inserted {
                    return DeviceCodeCreateResult::Collision;
                }
            }
        }

        let formatted = format_user_code(user_code);
        let verification_uri_complete = Some(format!("{verification_uri}?user_code={formatted}"));

        DeviceCodeCreateResult::Created(DeviceAuthorizationResponse {
            device_code,
            user_code: formatted,
            verification_uri: verification_uri.to_string(),
            verification_uri_complete,
            expires_in: self.ttl.as_secs(),
            interval: self.default_interval_secs,
        })
    }
}
