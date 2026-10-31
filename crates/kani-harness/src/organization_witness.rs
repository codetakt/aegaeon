//! Direct native-adapter preconditions. This is not the SQL/durability refinement.
use aegaeon_pure::organization_witness::{transition_revision, Action, Phase};

fn phase() -> Phase {
    match kani::any::<u8>() % 3 {
        0 => Phase::Fenced,
        1 => Phase::Prepared,
        _ => Phase::Active,
    }
}
fn action() -> Action {
    match kani::any::<u8>() % 3 {
        0 => Action::Fence,
        1 => Action::Prepare,
        _ => Action::Activate,
    }
}

#[kani::proof]
fn transition_revision_exact_domain() {
    let phase = phase();
    let action = action();
    let revision: i64 = kani::any();
    let pending: u32 = kani::any();
    let next = i128::from(revision) + 1;
    let phase_allowed = match action {
        Action::Fence => true,
        Action::Prepare => phase == Phase::Fenced && pending == 0,
        Action::Activate => phase == Phase::Prepared && pending == 0,
    };
    let last = i128::from(i64::MAX) - if action == Action::Fence { 0 } else { 1 };
    let expected = revision > 0 && pending <= 64 && phase_allowed && next <= last;
    let actual = transition_revision(phase, revision, pending, action);
    assert_eq!(actual.is_some(), expected);
    if let Some(value) = actual {
        assert_eq!(i128::from(value), next);
    }
}

#[kani::proof]
fn pending_work_cannot_prepare_or_activate() {
    let phase = phase();
    let revision: i64 = kani::any();
    let pending: u32 = kani::any();
    kani::assume(pending > 0);
    assert!(transition_revision(phase, revision, pending, Action::Prepare).is_none());
    assert!(transition_revision(phase, revision, pending, Action::Activate).is_none());
}

#[kani::proof]
fn successful_activation_preserves_terminal_fence() {
    let phase = phase();
    let revision: i64 = kani::any();
    let pending: u32 = kani::any();
    if let Some(next) = transition_revision(phase, revision, pending, Action::Activate) {
        assert!(next > revision);
        assert!(transition_revision(Phase::Active, next, 0, Action::Fence).is_some());
    }
    let terminal = transition_revision(Phase::Active, i64::MAX - 1, 64, Action::Fence);
    assert_eq!(terminal, Some(i64::MAX));
    assert!(transition_revision(Phase::Fenced, i64::MAX, 0, Action::Prepare).is_none());
}
