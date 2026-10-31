//! Production arithmetic for Organizations revisions and selected-token expiry.
//! These helpers do not authenticate callers or establish storage freshness.

/// Reserve the last positive revision for a terminal revocation.
#[must_use]
pub fn next_revision(value: i64, terminal: bool) -> Option<i64> {
    value
        .checked_add(1)
        .filter(|next| *next > 0 && (terminal || *next < i64::MAX))
}

/// Fold one positive retained role version into a policy revision starting at 1.
/// Refuse invalid inputs and exhaustion instead of wrapping or saturating.
#[must_use]
pub fn add_role_version(revision: i64, version: i64) -> Option<i64> {
    if revision < 1 || version < 1 {
        return None;
    }
    revision.checked_add(version).filter(|sum| *sum < i64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifetimeError {
    Overflow,
    NotLive,
}

/// Preserve the original grant and parent horizons and the 300-second profile.
pub fn selected_expiry(ceiling: i64, parent: i64, now: i64) -> Result<i64, LifetimeError> {
    let limit = now.checked_add(300).ok_or(LifetimeError::Overflow)?;
    let expiry = ceiling.min(parent).min(limit);
    if now < 0 || expiry <= now {
        Err(LifetimeError::NotLive)
    } else {
        Ok(expiry)
    }
}

/// Absolute original-MFA horizon; activation cannot restart its 300-second clock.
pub fn administrative_expiry(
    root: i64,
    parent: i64,
    auth_time: i64,
    now: i64,
) -> Result<i64, LifetimeError> {
    if auth_time <= 0 || now < auth_time {
        return Err(LifetimeError::NotLive);
    }
    let horizon = auth_time.checked_add(300).ok_or(LifetimeError::Overflow)?;
    selected_expiry(root.min(horizon), parent, now)
}
