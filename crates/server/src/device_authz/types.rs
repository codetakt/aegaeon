use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::time::Instant;
use std::time::SystemTime;

/// Status of a device authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceAuthzStatus {
    /// Waiting for the end user to authorize.
    Pending,
    /// The end user has approved the authorization; contains the granted subject + scope.
    Approved {
        user_id: String,
        scope: Option<String>,
    },
    /// The end user explicitly denied the authorization.
    Denied,
    /// The device code has expired.
    Expired,
}

/// Internal entry stored in the device code store.
#[derive(Debug, Clone)]
pub(super) struct DeviceCodeEntry {
    /// The user-facing code (stored for lookup by user code).
    #[cfg(test)]
    pub(super) user_code: String,
    /// Client that initiated the request.
    pub(super) client_id: String,
    /// Requested scope.
    pub(super) scope: Option<String>,
    /// Requested RFC 8707 resource indicator.
    pub(super) resource: Option<String>,
    /// Environment ID for multi-tenant scoping (DA-7).
    pub(super) environment_id: Option<String>,
    /// Authorization status.
    pub(super) status: DeviceAuthzStatus,
    /// When this entry expires (absolute wall-clock time).
    pub(super) expires_at: SystemTime,
    /// Timestamp of the last poll from this device (monotonic, for DA-1 rate limiting).
    #[cfg(test)]
    pub(super) last_poll_at: Option<Instant>,
    /// Current effective poll interval for this device (increases on `slow_down`).
    pub(super) poll_interval_secs: u64,
    /// Whether the approval has been consumed (single-use, DA-5).
    pub(super) consumed: bool,
}

/// Result of a device authorization request.
#[derive(Debug, Clone)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code (returned to the client device).
    pub device_code: String,
    /// The end-user verification code.
    pub user_code: String,
    /// The end-user verification URI.
    pub verification_uri: String,
    /// Optional verification URI that includes the `user_code`.
    pub verification_uri_complete: Option<String>,
    /// Lifetime in seconds of the `device_code` and `user_code`.
    pub expires_in: u64,
    /// Minimum polling interval in seconds.
    pub interval: u64,
}

/// Pending authorization data resolved from a user-facing device code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceUserCodeLookup {
    /// Client that initiated the request.
    pub client_id: String,
    /// Requested scope.
    pub scope: Option<String>,
    /// Requested RFC 8707 resource indicator.
    pub resource: Option<String>,
}

/// Outcome of a token poll for the `device_code` grant type.
#[derive(Debug, Clone)]
pub enum DevicePollResult {
    /// Authorization is still pending. The client should continue polling.
    AuthorizationPending,
    /// Client is polling too fast. Increase interval.
    SlowDown,
    /// The device code has expired.
    ExpiredToken,
    /// The user denied the request.
    AccessDenied,
    /// Authorization was granted.
    Approved {
        user_id: String,
        scope: Option<String>,
        resource: Option<String>,
        client_id: String,
    },
    /// The token poll requested a resource outside the approved device grant.
    InvalidTarget,
}
