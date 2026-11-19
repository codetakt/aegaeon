//! Retry scheduling for stable logical notifications.
//!
//! A plan is not a send permit. The outbox must persist it under the current
//! attempt fence and recheck authority, generation and expiry before sending.
//! This component cannot change a payload, proof, recipient or message identity.

/// Includes the initial transport attempt, not just subsequent retries.
pub const MAX_ATTEMPTS: u8 = 5;
const INITIAL_DELAY_SECONDS: u64 = 60;
const MAX_BACKOFF_SECONDS: u64 = 900;

/// The transport observation remains distinct from retry exhaustion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportOutcome {
    /// Adapter acceptance; this does not certify delivery to an inbox.
    Accepted,
    Rejected,
    Retryable,
    /// The adapter may have accepted the message even though no reply arrived.
    Uncertain,
}

/// Already parsed, bounded transport metadata; HTTP parsing belongs to transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryAfter {
    DelaySeconds(u64),
    UnixSeconds(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletedAttempt {
    /// Durable count, incremented at claim; the initial attempt has count one.
    pub attempts: u8,
    pub observed_at: u64,
    pub outcome: TransportOutcome,
    pub retry_after: Option<RetryAfter>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    Accepted,
    Rejected,
    Expired,
    AttemptsExhausted,
    NoTimeForRetry,
}

impl StopReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::AttemptsExhausted => "exhausted",
            Self::NoTimeForRetry => "retry_deadline",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryPlan {
    /// Persist this time; process restarts must not resample its jitter.
    At(u64),
    /// This does not replace the last transport outcome with a definitive failure.
    Stop(StopReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidInput {
    AttemptCount,
    Jitter,
}

/// Plan only a subsequent attempt; the initial send is admitted by the outbox.
///
/// `jitter_seconds` must be independently sampled by the worker in the inclusive
/// range `0..=jitter_limit(attempts)`. It cannot shorten the minimum backoff or a
/// Retry-After lower bound. `expires_at` is the original message deadline.
///
/// # Errors
/// Returns an error for an invalid completed-attempt count or out-of-range jitter.
pub fn plan(
    completed: CompletedAttempt,
    expires_at: u64,
    jitter_seconds: u64,
) -> Result<RetryPlan, InvalidInput> {
    let limit = jitter_limit(completed.attempts)?;
    match completed.outcome {
        TransportOutcome::Accepted => return Ok(RetryPlan::Stop(StopReason::Accepted)),
        TransportOutcome::Rejected => return Ok(RetryPlan::Stop(StopReason::Rejected)),
        TransportOutcome::Retryable | TransportOutcome::Uncertain => {}
    }
    if completed.observed_at >= expires_at {
        return Ok(RetryPlan::Stop(StopReason::Expired));
    }
    if completed.attempts == MAX_ATTEMPTS {
        return Ok(RetryPlan::Stop(StopReason::AttemptsExhausted));
    }
    if jitter_seconds > limit {
        return Err(InvalidInput::Jitter);
    }
    let delay = minimum_delay(completed.attempts) + jitter_seconds;
    let Some(backoff_at) = completed.observed_at.checked_add(delay) else {
        return Ok(RetryPlan::Stop(StopReason::NoTimeForRetry));
    };
    let retry_after_at = match completed.retry_after {
        None => completed.observed_at,
        Some(RetryAfter::UnixSeconds(at)) => at,
        Some(RetryAfter::DelaySeconds(delay)) => {
            let Some(at) = completed.observed_at.checked_add(delay) else {
                return Ok(RetryPlan::Stop(StopReason::NoTimeForRetry));
            };
            at
        }
    };
    let at = backoff_at.max(retry_after_at);
    Ok(if at < expires_at {
        RetryPlan::At(at)
    } else {
        RetryPlan::Stop(StopReason::NoTimeForRetry)
    })
}

/// Inclusive bound for one retry's extra delay; zero when no attempts remain.
///
/// # Errors
/// Returns an error unless the completed-attempt count is between one and five.
pub fn jitter_limit(attempts: u8) -> Result<u64, InvalidInput> {
    if !(1..=MAX_ATTEMPTS).contains(&attempts) {
        return Err(InvalidInput::AttemptCount);
    }
    if attempts == MAX_ATTEMPTS {
        return Ok(0);
    }
    let minimum = minimum_delay(attempts);
    Ok(minimum.min(MAX_BACKOFF_SECONDS - minimum))
}

fn minimum_delay(attempts: u8) -> u64 {
    // Called only after validating 1..=MAX_ATTEMPTS, and never for attempt five.
    INITIAL_DELAY_SECONDS << (attempts - 1)
}

#[cfg(test)]
mod tests;
