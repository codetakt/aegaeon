//! Registered action meaning is independent of resource-selector expansion.

pub(crate) const REGISTRY_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    ReadUsers,
    ReadTeams,
    ReadTenants,
    ReadEnvironments,
    ReadOrganizations,
}

impl Action {
    pub(crate) fn from_id(value: &str) -> Option<Self> {
        match value {
            "inventory.users.read" => Some(Self::ReadUsers),
            "inventory.teams.read" => Some(Self::ReadTeams),
            "inventory.tenants.read" => Some(Self::ReadTenants),
            "inventory.environments.read" => Some(Self::ReadEnvironments),
            "inventory.organizations.read" => Some(Self::ReadOrganizations),
            _ => None,
        }
    }

    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::ReadUsers => "inventory.users.read",
            Self::ReadTeams => "inventory.teams.read",
            Self::ReadTenants => "inventory.tenants.read",
            Self::ReadEnvironments => "inventory.environments.read",
            Self::ReadOrganizations => "inventory.organizations.read",
        }
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A bounded set of explicit registered actions, never an implied wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActionSet(u8);

impl ActionSet {
    pub(crate) fn from_actions(actions: &[Action]) -> Option<Self> {
        if actions.is_empty() || actions.len() > 5 {
            return None;
        }
        let mut set = 0;
        for action in actions {
            if set & action.bit() != 0 {
                return None;
            }
            set |= action.bit();
        }
        Some(Self(set))
    }

    pub(crate) fn contains(self, action: Action) -> bool {
        self.0 & action.bit() != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionPolicy {
    Enumerated(ActionSet),
    AllCurrentAndFuture { acknowledged_registry_version: u32 },
}

impl ActionPolicy {
    pub(crate) fn allows(self, action: Action) -> bool {
        match self {
            Self::Enumerated(set) => set.contains(action),
            Self::AllCurrentAndFuture {
                acknowledged_registry_version,
            } => (1..=REGISTRY_VERSION).contains(&acknowledged_registry_version),
        }
    }

    /// One complete parent policy must cover a child. Callers must never union
    /// policies from separate grants to manufacture this delegation envelope.
    pub(crate) fn is_subset_of(self, parent: Self) -> bool {
        match (self, parent) {
            (Self::Enumerated(child), Self::Enumerated(parent)) => child.0 & !parent.0 == 0,
            (
                _,
                Self::AllCurrentAndFuture {
                    acknowledged_registry_version,
                },
            ) => {
                (1..=REGISTRY_VERSION).contains(&acknowledged_registry_version)
                    && match self {
                        Self::Enumerated(_) => true,
                        Self::AllCurrentAndFuture {
                            acknowledged_registry_version,
                        } => (1..=REGISTRY_VERSION).contains(&acknowledged_registry_version),
                    }
            }
            (Self::AllCurrentAndFuture { .. }, Self::Enumerated(_)) => false,
        }
    }
}

#[cfg(test)]
mod tests;
