//! Exact upstream authorization deadline arithmetic, shared by production and Kani.
//!
//! SystemTime representability and the wall clock remain platform contracts. These
//! helpers do not establish Redis expiry, script atomicity, or clock agreement.
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadlineError {
    InvalidNanoseconds,
    TimestampOverflow,
    Expired,
    TtlOverflow,
}

impl DeadlineError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidNanoseconds => "invalid expiry nanoseconds",
            Self::TimestampOverflow => "expiry timestamp overflow",
            Self::Expired => "upstream auth state is already expired",
            Self::TtlOverflow => "upstream auth ttl overflow",
        }
    }
}

pub fn epoch_duration(secs: u64, nanos: u32) -> Result<Duration, DeadlineError> {
    if nanos >= 1_000_000_000 {
        return Err(DeadlineError::InvalidNanoseconds);
    }
    Ok(Duration::new(secs, nanos))
}

pub fn system_time_from_epoch_parts(secs: u64, nanos: u32) -> Result<SystemTime, DeadlineError> {
    SystemTime::UNIX_EPOCH
        .checked_add(epoch_duration(secs, nanos)?)
        .ok_or(DeadlineError::TimestampOverflow)
}

/// Round a positive remaining duration up so Redis cannot expire it early.
pub fn positive_ttl_millis(ttl: Duration) -> Result<u64, DeadlineError> {
    if ttl.is_zero() {
        return Err(DeadlineError::Expired);
    }
    let millis = ttl.as_millis() + u128::from(ttl.subsec_nanos() % 1_000_000 != 0);
    u64::try_from(millis).map_err(|_| DeadlineError::TtlOverflow)
}

pub fn redis_ttl_millis_at(expires_at: SystemTime, now: SystemTime) -> Result<u64, DeadlineError> {
    let ttl = expires_at
        .duration_since(now)
        .map_err(|_| DeadlineError::Expired)?;
    positive_ttl_millis(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ceiling_at_u64_millisecond_limit() {
        let maximum = Duration::from_millis(u64::MAX);
        assert_eq!(positive_ttl_millis(maximum), Ok(u64::MAX));
        assert_eq!(
            positive_ttl_millis(maximum - Duration::from_nanos(1)),
            Ok(u64::MAX)
        );
        assert_eq!(
            positive_ttl_millis(maximum + Duration::from_nanos(1)),
            Err(DeadlineError::TtlOverflow)
        );
        assert_eq!(
            positive_ttl_millis(Duration::ZERO),
            Err(DeadlineError::Expired)
        );
        assert_eq!(positive_ttl_millis(Duration::from_nanos(1)), Ok(1));
    }

    #[test]
    fn fraction_validation_never_normalizes_invalid_fields() {
        assert_eq!(epoch_duration(u64::MAX, 999_999_999), Ok(Duration::MAX));
        for nanos in [1_000_000_000, u32::MAX] {
            assert_eq!(
                epoch_duration(u64::MAX, nanos),
                Err(DeadlineError::InvalidNanoseconds)
            );
        }
    }
}
