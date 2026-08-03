//! RFC 8628 — OAuth 2.0 Device Authorization Grant
//!
//! Implements the device authorization endpoint, device code store with
//! TTL-based expiry, user code generation with entropy guarantees, and
//! polling semantics (`authorization_pending`, `slow_down`, `expired_token`).
//!
//! Security properties enforced:
//! - DA-1: Rate limiting via per-device_code poll interval + `slow_down` backoff
//! - DA-2: User code entropy ≥ 31 bits (8 chars from 20-char alphabet → log₂(20⁸) ≈ 34.6 bits)
//! - DA-3: `device_code` stored as SHA-256 hash (raw value never persisted)
//! - DA-4: `device_code` has 256 bits of entropy (32 bytes, base64url)
//! - DA-5: Single-use after authorization (atomic CAS on status)
//! - DA-6: Scoped TTL with configurable expiry
//! - DA-7: Environment-scoped device codes

#[cfg(test)]
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Slow-down increment: added to client's interval on each `slow_down` response.
const SLOW_DOWN_INCREMENT_SECS: u64 = 5;

mod codes;
mod csrf;
mod rate_limit;
mod redis_backend;
mod rendering;
mod store;
mod types;

#[cfg(test)]
use codes::{
    format_user_code, generate_device_code, hash_device_code, normalize_user_code,
    user_code_char_from_random_byte, USER_CODE_ALPHABET,
};

#[cfg(test)]
use redis_backend::{RedisDeviceCodeKeyspace, RedisDeviceCodeStoreBackend};

pub use csrf::{CsrfTokenStore, CsrfTokenStoreError};
pub use rate_limit::VerificationRateLimiter;
pub use rendering::{render_confirm_page, render_result_page, render_user_code_form};
pub use store::DeviceCodeStore;
pub use types::{
    DeviceAuthorizationResponse, DeviceAuthzStatus, DevicePollResult, DeviceUserCodeLookup,
};

#[cfg(test)]
use store::{DeviceCodeCreateResult, DeviceCodeStoreBackend};
#[cfg(test)]
use types::DeviceCodeEntry;

#[cfg(test)]
fn device_lock_error(error: impl std::fmt::Display, operation: &'static str, kind: &str) -> String {
    let message = format!("device authorization {kind} lock poisoned: {error}");
    tracing::error!(error = %message, operation, "device authorization store operation failed");
    message
}

#[cfg(test)]
fn read_lock<'a, T>(
    lock: &'a RwLock<T>,
    operation: &'static str,
) -> Result<RwLockReadGuard<'a, T>, String> {
    lock.read()
        .map_err(|err| device_lock_error(err, operation, "read"))
}

#[cfg(test)]
pub(super) fn write_lock<'a, T>(
    lock: &'a RwLock<T>,
    operation: &'static str,
) -> Result<RwLockWriteGuard<'a, T>, String> {
    lock.write()
        .map_err(|err| device_lock_error(err, operation, "write"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
