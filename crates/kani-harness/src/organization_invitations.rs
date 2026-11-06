//! Actual lifetime helpers; no clock, recipient, database or delivery proof.
use aegaeon_pure::organization_invitations::{
    challenge_deadline, invitation_deadline, is_live, Purpose,
};

#[kani::proof]
fn invitation_deadline_exact_integer_domain() {
    let issued: i64 = kani::any();
    let explicit: bool = kani::any();
    let requested: i64 = kani::any();
    let lifetime = if explicit {
        i128::from(requested)
    } else {
        86_400
    };
    let expected = i128::from(issued) + lifetime;
    let permitted =
        issued >= 0 && lifetime >= 60 && lifetime <= 86_400 && expected <= i128::from(i64::MAX);
    let actual = invitation_deadline(issued, explicit.then_some(requested));
    assert_eq!(actual.is_some(), permitted);
    if let Some(expiry) = actual {
        assert_eq!(i128::from(expiry), expected);
    }
}

#[kani::proof]
fn recipient_challenge_deadline_exact_integer_domain() {
    let issued: i64 = kani::any();
    let expected = i128::from(issued) + 300;
    let permitted = issued >= 0 && expected <= i128::from(i64::MAX);
    let actual = challenge_deadline(issued);
    assert_eq!(actual.is_some(), permitted);
    if let Some(expiry) = actual {
        assert_eq!(i128::from(expiry), expected);
    }
}

#[kani::proof]
fn capability_window_exact_integer_domain() {
    let selector: u8 = kani::any();
    kani::assume(selector < 4);
    let (purpose, minimum, maximum) = match selector {
        0 => (Purpose::Invitation, 60, 86_400),
        1 => (Purpose::RecipientChallenge, 1, 300),
        2 => (Purpose::IdentityRegistration, 1, 600),
        _ => (Purpose::IdentityRecovery, 1, 600),
    };
    let issued: i64 = kani::any();
    let expiry: i64 = kani::any();
    let now: i64 = kani::any();
    let duration = i128::from(expiry) - i128::from(issued);
    let permitted =
        issued >= 0 && now >= issued && now < expiry && duration >= minimum && duration <= maximum;
    assert_eq!(is_live(purpose, issued, expiry, now), permitted);
}
