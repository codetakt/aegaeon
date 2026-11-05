//! Exact invitation lifetime arithmetic; caller, clock and storage remain external.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Invitation,
    RecipientChallenge,
    IdentityRegistration,
    IdentityRecovery,
}

pub const DEFAULT_INVITATION_SECONDS: i64 = 86_400;
pub const RECIPIENT_CHALLENGE_SECONDS: i64 = 300;
pub const IDENTITY_PROOF_SECONDS: i64 = 600;

#[must_use]
pub fn invitation_deadline(issued_at: i64, requested: Option<i64>) -> Option<i64> {
    let lifetime = requested.unwrap_or(DEFAULT_INVITATION_SECONDS);
    if issued_at < 0 || !(60..=DEFAULT_INVITATION_SECONDS).contains(&lifetime) {
        return None;
    }
    issued_at.checked_add(lifetime)
}

#[must_use]
pub fn challenge_deadline(issued_at: i64) -> Option<i64> {
    (issued_at >= 0)
        .then_some(issued_at)?
        .checked_add(RECIPIENT_CHALLENGE_SECONDS)
}

#[must_use]
pub fn is_live(purpose: Purpose, issued_at: i64, expires_at: i64, now: i64) -> bool {
    let (minimum, maximum) = match purpose {
        Purpose::Invitation => (60, DEFAULT_INVITATION_SECONDS),
        Purpose::RecipientChallenge => (1, RECIPIENT_CHALLENGE_SECONDS),
        Purpose::IdentityRegistration | Purpose::IdentityRecovery => (1, IDENTITY_PROOF_SECONDS),
    };
    issued_at >= 0
        && issued_at <= now
        && now < expires_at
        && expires_at
            .checked_sub(issued_at)
            .is_some_and(|duration| (minimum..=maximum).contains(&duration))
}
