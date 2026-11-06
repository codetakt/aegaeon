//! Primary creation disposition used by the single and batch transactions.
//! Inputs are observations, not authorization or evidence constructors.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Reserved,
    Retryable,
    Committed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Apply,
    Replay,
    Reconcile,
}

/// `exact_primary` is supplied only after successful full immutable-record
/// comparison. A storage or comparison error must never become `false`.
pub fn decide(state: State, exact_primary: bool) -> Decision {
    match (state, exact_primary) {
        (State::Reserved, false) => Decision::Apply,
        (State::Committed, true) => Decision::Replay,
        _ => Decision::Reconcile,
    }
}

/// Fold a nonempty batch without permitting mixed mutation and replay.
/// The caller separately enforces the batch bound and rejects an empty result.
pub fn extend_batch(previous: Option<Decision>, next: Decision) -> Decision {
    match previous {
        None => next,
        Some(value) if value == next => value,
        Some(_) => Decision::Reconcile,
    }
}
