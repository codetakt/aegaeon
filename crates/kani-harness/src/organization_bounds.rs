//! Direct production helpers over all i64 inputs, with independent i128 oracles.
//! No database, authentication, caller, clock-supplier or release-artifact proof.
use aegaeon_pure::organization_bounds::{
    add_role_version, administrative_expiry, next_revision, selected_expiry, LifetimeError,
};

#[kani::proof]
fn role_policy_fold_exact_integer_domain() {
    let revision: i64 = kani::any();
    let version: i64 = kani::any();
    let sum = i128::from(revision) + i128::from(version);
    let result = add_role_version(revision, version);
    let valid = revision >= 1 && version >= 1 && sum < i128::from(i64::MAX);
    assert_eq!(result.is_some(), valid);
    if let Some(next) = result {
        assert_eq!(i128::from(next), sum);
        assert!(next > revision && next > version);
        assert!(next_revision(next, true).is_some());
    }
}

#[kani::proof]
fn revision_exact_integer_domain() {
    let value: i64 = kani::any();
    let terminal: bool = kani::any();
    let result = next_revision(value, terminal);
    let successor = i128::from(value) + 1;
    let last = i128::from(i64::MAX) - if terminal { 0 } else { 1 };
    assert_eq!(result.is_some(), successor >= 1 && successor <= last);
    if let Some(next) = result {
        assert_eq!(i128::from(next), successor);
        assert!(next > 0);
    }
}

#[kani::proof]
fn nonterminal_success_preserves_terminal_capacity() {
    let value: i64 = kani::any();
    if let Some(next) = next_revision(value, false) {
        let terminal = next_revision(next, true);
        assert!(terminal.is_some());
        if let Some(last) = terminal {
            assert_eq!(i128::from(last), i128::from(next) + 1);
        }
    }
    assert_eq!(next_revision(i64::MAX - 1, false), None);
    assert_eq!(next_revision(i64::MAX - 1, true), Some(i64::MAX));
    assert_eq!(next_revision(i64::MAX, true), None);
}

#[kani::proof]
fn selected_expiry_exact_integer_domain() {
    let ceiling: i64 = kani::any();
    let parent: i64 = kani::any();
    let now: i64 = kani::any();
    let result = selected_expiry(ceiling, parent, now);
    let horizon = i128::from(now) + 300;
    if horizon > i128::from(i64::MAX) {
        assert_eq!(result, Err(LifetimeError::Overflow));
    } else {
        let expected = i128::from(ceiling).min(i128::from(parent)).min(horizon);
        if now < 0 || expected <= i128::from(now) {
            assert_eq!(result, Err(LifetimeError::NotLive));
        } else {
            assert!(result.is_ok());
            if let Ok(expiry) = result {
                assert_eq!(i128::from(expiry), expected);
                assert!(expiry > now && expiry <= ceiling && expiry <= parent);
                assert!(i128::from(expiry) - i128::from(now) <= 300);
            }
        }
    }
}

#[kani::proof]
fn administrative_expiry_exact_integer_domain() {
    let root: i64 = kani::any();
    let parent: i64 = kani::any();
    let auth: i64 = kani::any();
    let now: i64 = kani::any();
    let result = administrative_expiry(root, parent, auth, now);
    let horizon = i128::from(auth) + 300;
    let current_limit = i128::from(now) + 300;
    if auth <= 0 || now < auth {
        assert_eq!(result, Err(LifetimeError::NotLive));
    } else if horizon > i128::from(i64::MAX) || current_limit > i128::from(i64::MAX) {
        assert_eq!(result, Err(LifetimeError::Overflow));
    } else {
        let expected = i128::from(root).min(i128::from(parent)).min(horizon);
        if expected <= i128::from(now) {
            assert_eq!(result, Err(LifetimeError::NotLive));
        } else {
            assert!(result.is_ok());
            if let Ok(expiry) = result {
                assert_eq!(i128::from(expiry), expected);
                assert!(expiry > now && expiry <= root && expiry <= parent);
                assert!(i128::from(expiry) - i128::from(auth) <= 300);
            }
        }
    }
}

#[kani::proof]
fn administrative_activation_never_slides_mfa_deadline() {
    let root: i64 = kani::any();
    let parent: i64 = kani::any();
    let auth: i64 = kani::any();
    let first: i64 = kani::any();
    let later: i64 = kani::any();
    if let (Ok(a), Ok(b)) = (
        administrative_expiry(root, parent, auth, first),
        administrative_expiry(root, parent, auth, later),
    ) {
        assert_eq!(a, b);
    }
}
