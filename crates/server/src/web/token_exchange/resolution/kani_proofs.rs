//! Direct production expiry check over the pinned Linux SystemTime domain:
//! all i64 second fields, all nanosecond fields, and every positive u64 TTL.
//! SystemTime construction, subtraction and the production helper are not stubbed.
use super::token_exchange_expires_in;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn timestamp(seconds: i64, nanos: u32) -> SystemTime {
    let whole = if seconds < 0 {
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
    };
    whole
        .expect("every i64 second is representable on this target")
        .checked_add(Duration::from_nanos(u64::from(nanos)))
        .expect("every subsecond field is representable on this target")
}

#[kani::proof]
#[kani::unwind(4)]
fn verify_exchange_lifetime_linux() {
    let now_secs: i64 = kani::any();
    let end_secs: i64 = kani::any();
    let now_nanos: u32 = kani::any();
    let end_nanos: u32 = kani::any();
    let ttl: u64 = kani::any();
    kani::assume(now_nanos < 1_000_000_000);
    kani::assume(end_nanos < 1_000_000_000);
    kani::assume(ttl > 0);
    let now = timestamp(now_secs, now_nanos);
    let deadline = timestamp(end_secs, end_nanos);
    let result = token_exchange_expires_in(deadline, now, ttl);
    let remaining =
        i128::from(end_secs) - i128::from(now_secs) - if end_nanos < now_nanos { 1 } else { 0 };
    let expected = if remaining <= 0 {
        None
    } else {
        assert!(
            remaining <= i128::from(u64::MAX),
            "duration fits u64 seconds"
        );
        let seconds = remaining as u64;
        Some(if seconds < ttl { seconds } else { ttl })
    };
    assert_eq!(result, expected);
    if let Some(seconds) = result {
        assert!(seconds > 0 && seconds <= ttl);
        assert!(
            now.checked_add(Duration::from_secs(seconds))
                .is_some_and(|end| end <= deadline),
            "output does not outlive the subject"
        );
    }
}
