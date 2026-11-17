use super::*;

fn attempt(attempts: u8, observed_at: u64) -> CompletedAttempt {
    CompletedAttempt {
        attempts,
        observed_at,
        outcome: TransportOutcome::Uncertain,
        retry_after: None,
    }
}

#[test]
fn completed_delivery_and_definitive_refusal_never_retry() {
    for (outcome, reason) in [
        (TransportOutcome::Accepted, StopReason::Accepted),
        (TransportOutcome::Rejected, StopReason::Rejected),
    ] {
        let completed = CompletedAttempt {
            outcome,
            ..attempt(1, 100)
        };
        for expiry in [0, 100, u64::MAX] {
            assert_eq!(plan(completed, expiry, 0), Ok(RetryPlan::Stop(reason)));
        }
    }
}

#[test]
fn budget_counts_initial_attempt_and_never_replenishes_uncertain_work() {
    assert_eq!(
        plan(attempt(5, 100), 10_000, 0),
        Ok(RetryPlan::Stop(StopReason::AttemptsExhausted))
    );
    assert_eq!(jitter_limit(5), Ok(0));
    for attempts in [0, 6, u8::MAX] {
        assert_eq!(
            plan(attempt(attempts, 100), 10_000, 0),
            Err(InvalidInput::AttemptCount)
        );
    }
}

#[test]
fn backoff_and_jitter_stay_within_each_attempts_bounds() {
    for (attempts, earliest, latest) in [(1, 60, 120), (2, 120, 240), (3, 240, 480), (4, 480, 900)]
    {
        let limit = jitter_limit(attempts).unwrap();
        assert_eq!(
            plan(attempt(attempts, 1_000), 10_000, 0),
            Ok(RetryPlan::At(1_000 + earliest))
        );
        assert_eq!(
            plan(attempt(attempts, 1_000), 10_000, limit),
            Ok(RetryPlan::At(1_000 + latest))
        );
        for jitter in 0..=limit {
            let RetryPlan::At(at) = plan(attempt(attempts, 1_000), 10_000, jitter).unwrap() else {
                panic!("valid retry unexpectedly refused");
            };
            assert!((1_000 + earliest..=1_000 + latest).contains(&at));
        }
        assert_eq!(
            plan(attempt(attempts, 1_000), 10_000, limit + 1),
            Err(InvalidInput::Jitter)
        );
    }
}

#[test]
fn retry_after_can_exceed_backoff_cap_but_never_message_deadline() {
    for retry_after in [
        RetryAfter::DelaySeconds(3_600),
        RetryAfter::UnixSeconds(3_700),
    ] {
        let completed = CompletedAttempt {
            retry_after: Some(retry_after),
            ..attempt(1, 100)
        };
        assert_eq!(plan(completed, 3_701, 60), Ok(RetryPlan::At(3_700)));
        for expiry in [200, 3_699, 3_700] {
            assert_eq!(
                plan(completed, expiry, 60),
                Ok(RetryPlan::Stop(StopReason::NoTimeForRetry))
            );
        }
    }
}

#[test]
fn stale_or_zero_retry_after_never_removes_backoff() {
    for retry_after in [
        RetryAfter::DelaySeconds(0),
        RetryAfter::UnixSeconds(0),
        RetryAfter::UnixSeconds(100),
    ] {
        let completed = CompletedAttempt {
            retry_after: Some(retry_after),
            ..attempt(2, 100)
        };
        assert_eq!(plan(completed, 10_000, 20), Ok(RetryPlan::At(240)));
    }
}

#[test]
fn expiry_is_exclusive_and_never_extended() {
    let completed = attempt(1, 100);
    for expiry in [0, 99, 100] {
        assert_eq!(
            plan(completed, expiry, 0),
            Ok(RetryPlan::Stop(StopReason::Expired))
        );
    }
    for expiry in [101, 159, 160] {
        assert_eq!(
            plan(completed, expiry, 0),
            Ok(RetryPlan::Stop(StopReason::NoTimeForRetry))
        );
    }
    assert_eq!(plan(completed, 161, 0), Ok(RetryPlan::At(160)));
}

#[test]
fn timestamp_overflow_never_wraps_to_an_early_retry() {
    assert_eq!(
        plan(attempt(1, u64::MAX - 10), u64::MAX, 0),
        Ok(RetryPlan::Stop(StopReason::NoTimeForRetry))
    );
    let completed = CompletedAttempt {
        retry_after: Some(RetryAfter::DelaySeconds(u64::MAX)),
        ..attempt(1, 100)
    };
    assert_eq!(
        plan(completed, u64::MAX, 0),
        Ok(RetryPlan::Stop(StopReason::NoTimeForRetry))
    );
    let completed = CompletedAttempt {
        retry_after: Some(RetryAfter::UnixSeconds(u64::MAX)),
        ..attempt(1, 100)
    };
    assert_eq!(
        plan(completed, u64::MAX, 0),
        Ok(RetryPlan::Stop(StopReason::NoTimeForRetry))
    );
}

#[test]
fn retryable_and_uncertain_outcomes_share_timing_without_becoming_rejected() {
    for attempts in 1..=MAX_ATTEMPTS {
        for expires_at in [0, 100, 101, 160, 1_000, 10_000] {
            let uncertain = attempt(attempts, 100);
            let retryable = CompletedAttempt {
                outcome: TransportOutcome::Retryable,
                ..uncertain
            };
            let left = plan(uncertain, expires_at, 0);
            assert_eq!(left, plan(retryable, expires_at, 0));
            assert!(!matches!(
                left,
                Ok(RetryPlan::Stop(StopReason::Accepted | StopReason::Rejected))
            ));
            if let Ok(RetryPlan::At(at)) = left {
                assert!(at > uncertain.observed_at && at < expires_at);
            }
        }
    }
}
