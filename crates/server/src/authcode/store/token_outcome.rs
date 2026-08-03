pub(super) enum TokenRevocationOutcome {
    AccessToken,
    RefreshToken { child_count: usize },
    BearerMeta,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRotationError {
    Invalid,
    Expired,
    Reused,
    InconsistentGrant,
    BackendUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientBoundRevocationOutcome {
    Revoked,
    Unknown,
    OwnerMismatch,
}
