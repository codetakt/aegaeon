#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::LazyLock;

// Re-export JoseContext from FFI layer
pub use ffi::JoseContext;

/// Default maximum length (in characters) for Base64URL-encoded JOSE protected headers.
pub const DEFAULT_HEADER_MAX_LEN: usize = 4096;

/// Maximum allowed length for the optional `kid` field.
pub const KID_MAX_LEN: usize = 255;

#[cfg(test)]
static HEADER_MAX_LEN: LazyLock<AtomicUsize> =
    LazyLock::new(|| AtomicUsize::new(DEFAULT_HEADER_MAX_LEN));

/// Returns the currently configured header length limit.
///
/// # Deprecated
///
/// This legacy convenience API is deprecated.
/// Use `JoseContext` or a caller-owned runtime policy for per-request configuration instead.
///
/// # Migration
///
/// ```rust,ignore
/// // Old (deprecated):
/// let max_len = policy::header_max_len();
///
/// // New (recommended):
/// let context = JoseContext::default();
/// let max_len = context.header_max_length();
/// ```
#[deprecated(
    since = "0.1.0",
    note = "Use JoseContext for per-request configuration"
)]
pub fn header_max_len() -> usize {
    #[cfg(test)]
    {
        HEADER_MAX_LEN.load(Ordering::Relaxed)
    }
    #[cfg(not(test))]
    {
        DEFAULT_HEADER_MAX_LEN
    }
}

/// Updates the global header length limit.
///
/// The value must be a positive number. Callers should reset to the default after tests.
#[cfg(test)]
pub fn set_header_max_len(len: usize) {
    let value = if len == 0 {
        DEFAULT_HEADER_MAX_LEN
    } else {
        len
    };
    HEADER_MAX_LEN.store(value, Ordering::Relaxed);
}

#[cfg(test)]
pub fn reset_header_max_len() {
    HEADER_MAX_LEN.store(DEFAULT_HEADER_MAX_LEN, Ordering::Relaxed);
}
