use aegaeon_pure::organization_creation::{decide, extend_batch, Decision, State};

fn state() -> State {
    match kani::any::<u8>() {
        0 => State::Reserved,
        1 => State::Retryable,
        _ => State::Committed,
    }
}

fn decision() -> Decision {
    match kani::any::<u8>() {
        0 => Decision::Apply,
        1 => Decision::Replay,
        _ => Decision::Reconcile,
    }
}

#[kani::proof]
fn creation_disposition_exact_domain() {
    let state = state();
    let exact_primary = kani::any();
    let actual = decide(state, exact_primary);
    assert_eq!(
        actual == Decision::Apply,
        state == State::Reserved && !exact_primary
    );
    assert_eq!(
        actual == Decision::Replay,
        state == State::Committed && exact_primary
    );
    if state == State::Retryable
        || (state == State::Reserved && exact_primary)
        || (state == State::Committed && !exact_primary)
    {
        assert_eq!(actual, Decision::Reconcile);
    }
}

#[kani::proof]
fn creation_batch_uniformity_induction_step() {
    let previous = if kani::any() { Some(decision()) } else { None };
    let next = decision();
    let actual = extend_batch(previous, next);
    let applicable =
        next == Decision::Apply && (previous.is_none() || previous == Some(Decision::Apply));
    let replayable =
        next == Decision::Replay && (previous.is_none() || previous == Some(Decision::Replay));
    assert_eq!(actual == Decision::Apply, applicable);
    assert_eq!(actual == Decision::Replay, replayable);
    if previous == Some(Decision::Reconcile) || next == Decision::Reconcile {
        assert_eq!(actual, Decision::Reconcile);
    }
}
