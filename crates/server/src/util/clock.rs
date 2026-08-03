use std::fmt;
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

#[derive(Debug)]
pub enum UnixEpochSecsError {
    BeforeUnixEpoch(SystemTimeError),
    OutOfRange(u64),
}

impl fmt::Display for UnixEpochSecsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeUnixEpoch(error) => {
                write!(f, "system clock is before Unix epoch: {error}")
            }
            Self::OutOfRange(secs) => {
                write!(f, "Unix epoch seconds exceed i64 range: {secs}")
            }
        }
    }
}

impl std::error::Error for UnixEpochSecsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BeforeUnixEpoch(error) => Some(error),
            Self::OutOfRange(_) => None,
        }
    }
}

/// Convert a system time into Unix epoch seconds without collapsing clock
/// errors into epoch zero.
///
/// # Errors
///
/// Returns `SystemTimeError` when `value` is before the Unix epoch.
pub fn unix_epoch_secs(value: SystemTime) -> Result<u64, SystemTimeError> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
}

/// Return current Unix epoch seconds without treating a broken host clock as 0.
///
/// # Errors
///
/// Returns `SystemTimeError` when the current system clock is before the Unix epoch.
pub fn now_unix_epoch_secs() -> Result<u64, SystemTimeError> {
    unix_epoch_secs(SystemTime::now())
}

/// Convert a system time to signed Unix epoch seconds.
///
/// # Errors
///
/// Returns an error when the supplied time is before the Unix epoch or cannot
/// be represented as an `i64` Unix timestamp.
pub fn unix_epoch_secs_i64(value: SystemTime) -> Result<i64, UnixEpochSecsError> {
    let secs = unix_epoch_secs(value).map_err(UnixEpochSecsError::BeforeUnixEpoch)?;
    i64::try_from(secs).map_err(|_| UnixEpochSecsError::OutOfRange(secs))
}

/// Return current signed Unix epoch seconds.
///
/// # Errors
///
/// Returns an error when the current system clock is before the Unix epoch or
/// cannot be represented as an `i64` Unix timestamp.
pub fn now_unix_epoch_secs_i64() -> Result<i64, UnixEpochSecsError> {
    unix_epoch_secs_i64(SystemTime::now())
}

pub fn log_clock_error(context: &str, error: impl fmt::Display) {
    tracing::error!(%context, error = %error, "system clock is outside supported Unix epoch range");
}
