use super::super::DeviceAuthzStatus;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::device_authz) struct RedisDeviceCodeEntry {
    pub(in crate::device_authz) device_code_hash: String,
    pub(in crate::device_authz) user_code_lookup_key: String,
    pub(in crate::device_authz) client_id: String,
    pub(in crate::device_authz) scope: Option<String>,
    pub(in crate::device_authz) resource: Option<String>,
    pub(in crate::device_authz) environment_id: Option<String>,
    pub(in crate::device_authz) status: DeviceAuthzStatus,
    pub(in crate::device_authz) expires_at_ms: u64,
    pub(in crate::device_authz) last_poll_at_ms: Option<u64>,
    pub(in crate::device_authz) poll_interval_secs: u64,
    pub(in crate::device_authz) consumed: bool,
}

#[derive(Debug, Error)]
pub(in crate::device_authz) enum DeviceCodeStorageError {
    #[error("device code store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("device code store retention cannot be represented")]
    RetentionOverflow,
}
