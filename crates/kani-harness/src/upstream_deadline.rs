//! Calls the same unconditional helpers used by the server, without stubs.
//! Independent seconds/borrow and fraction-ceiling oracles avoid Duration rounding.
//! Linux SystemTime results apply only to the pinned x86_64 Linux toolchain.
use aegaeon_pure::upstream_deadline::{self as production, DeadlineError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[kani::proof]
#[kani::unwind(4)]
fn epoch_fraction_full_domain() {
    let seconds: u64 = kani::any();
    let nanos: u32 = kani::any();
    let result = production::epoch_duration(seconds, nanos);
    if nanos >= 1_000_000_000 {
        assert_eq!(result, Err(DeadlineError::InvalidNanoseconds));
    } else {
        let duration = result.expect("every canonical u64/u32 duration is accepted");
        assert_eq!(duration.as_secs(), seconds);
        assert_eq!(duration.subsec_nanos(), nanos);
        assert_eq!(
            duration.as_nanos(),
            u128::from(seconds) * 1_000_000_000 + u128::from(nanos)
        );
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn epoch_reconstruction_linux() {
    let seconds: u64 = kani::any();
    let nanos: u32 = kani::any();
    let result = production::system_time_from_epoch_parts(seconds, nanos);
    if nanos >= 1_000_000_000 {
        assert_eq!(result, Err(DeadlineError::InvalidNanoseconds));
    } else if seconds > i64::MAX as u64 {
        assert_eq!(result, Err(DeadlineError::TimestampOverflow));
    } else {
        let duration = result
            .expect("canonical Linux timestamp")
            .duration_since(UNIX_EPOCH)
            .unwrap();
        assert_eq!(duration.as_secs(), seconds);
        assert_eq!(duration.subsec_nanos(), nanos);
    }
}

// Oracle only: numerator rounding, unlike production floor plus a remainder bit.
fn fraction_ceiling(nanos: u32) -> u64 {
    (u64::from(nanos) + 999_999) / 1_000_000
}

#[kani::proof]
#[kani::unwind(4)]
fn fraction_ceiling_is_minimal() {
    let nanos: u32 = kani::any();
    kani::assume(nanos < 1_000_000_000);
    let millis = fraction_ceiling(nanos);
    assert!(millis * 1_000_000 >= u64::from(nanos));
    if nanos == 0 {
        assert_eq!(millis, 0);
    } else {
        assert!(millis > 0);
        assert!((millis - 1) * 1_000_000 < u64::from(nanos));
    }
}

// Adding an integer number of milliseconds preserves the least upper integer.
// The separate fraction lemma proves that property without a u64-domain bound.
fn expected_millis(seconds: u64, nanos: u32) -> Result<u64, DeadlineError> {
    let fraction = fraction_ceiling(nanos);
    let millis = u128::from(seconds) * 1000 + u128::from(fraction);
    if millis == 0 {
        Err(DeadlineError::Expired)
    } else if millis > u128::from(u64::MAX) {
        Err(DeadlineError::TtlOverflow)
    } else {
        Ok(millis as u64)
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn positive_ttl_ceiling_full_domain() {
    let seconds: u64 = kani::any();
    let nanos: u32 = kani::any();
    kani::assume(nanos < 1_000_000_000); // Exactly the Duration representation invariant.
    let result = production::positive_ttl_millis(Duration::new(seconds, nanos));
    assert_eq!(result, expected_millis(seconds, nanos));
}

fn linux_timestamp(seconds: i64, nanos: u32) -> SystemTime {
    let whole = if seconds < 0 {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
    };
    whole
        .expect("every Linux i64 second is representable")
        .checked_add(Duration::from_nanos(u64::from(nanos)))
        .expect("every canonical Linux nanosecond is representable")
}

#[kani::proof]
#[kani::unwind(4)]
fn strict_deadline_linux() {
    let end_seconds: i64 = kani::any();
    let now_seconds: i64 = kani::any();
    let end_nanos: u32 = kani::any();
    let now_nanos: u32 = kani::any();
    kani::assume(end_nanos < 1_000_000_000);
    kani::assume(now_nanos < 1_000_000_000);
    let end = linux_timestamp(end_seconds, end_nanos);
    let now = linux_timestamp(now_seconds, now_nanos);
    // Independent signed-seconds/borrow oracle; no SystemTime subtraction here.
    let borrow = end_nanos < now_nanos;
    let seconds = i128::from(end_seconds) - i128::from(now_seconds) - i128::from(borrow);
    let nanos = if borrow {
        end_nanos + 1_000_000_000 - now_nanos
    } else {
        end_nanos - now_nanos
    };
    assert!(nanos < 1_000_000_000);
    let expired = seconds < 0 || (seconds == 0 && nanos == 0);
    let expected = if expired {
        Err(DeadlineError::Expired)
    } else {
        assert!(seconds <= i128::from(u64::MAX));
        expected_millis(seconds as u64, nanos)
    };
    assert_eq!(production::redis_ttl_millis_at(end, now), expected);
    assert_eq!(now < end, !expired);
}
