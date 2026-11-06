//! Control-store transition preconditions used by the native witness adapter.
//! These scalar checks do not establish database durability or authenticated supply.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Fenced,
    Prepared,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Fence,
    Prepare,
    Activate,
}

pub const ADMISSION_SLOTS: u32 = 64;

/// Revision MAX is reserved for a permanent fence. No transition grants access
/// while work from the preceding selection can still be outstanding.
pub fn transition_revision(
    phase: Phase,
    revision: i64,
    pending: u32,
    action: Action,
) -> Option<i64> {
    if revision <= 0 || pending > ADMISSION_SLOTS {
        return None;
    }
    let allowed = match action {
        Action::Fence => true,
        Action::Prepare => phase == Phase::Fenced && pending == 0,
        Action::Activate => phase == Phase::Prepared && pending == 0,
    };
    if !allowed {
        return None;
    }
    super::organization_bounds::next_revision(revision, action == Action::Fence)
}
