use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const ORGANIZATION_ACCESS_TYPE: &str =
    "https://github.com/codetakt/aegaeon/spec/organization-access/v1";
pub const MAX_ROLES: usize = 64;
pub(super) const MAX_PRIVILEGES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("invalid organization authority data")]
    Invalid,
    #[error("organization authority does not permit the operation")]
    Forbidden,
    #[error("organization authority requires new authorization")]
    ReauthorizationRequired,
    #[error("organization authority revision has changed")]
    Conflict,
    #[error("organization representation precondition failed")]
    PreconditionFailed,
    #[error("organization authority revision is exhausted")]
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub environment_id: Uuid,
    pub domain_id: Uuid,
}

impl Scope {
    pub(super) fn validate(self) -> Result<(), AuthorityError> {
        require(!self.environment_id.is_nil() && !self.domain_id.is_nil())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum OrganizationState {
    Provisioning,
    Active,
    Suspended,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Organization {
    pub scope: Scope,
    pub id: Uuid,
    pub external_id: String,
    pub state: OrganizationState,
    pub revision: i64,
    pub grant_generation: i64,
}

impl Organization {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.scope.validate()?;
        require(
            !self.id.is_nil()
                && valid_external_id(&self.external_id)
                && self.revision > 0
                && self.grant_generation > 0,
        )
    }

    /// The repository must check current owner/provision authority and zero
    /// effective administrators under its member-identity locks.
    pub(crate) fn prepare_administrator_recovery(
        &mut self,
        expected: i64,
    ) -> Result<(), AuthorityError> {
        self.validate()?;
        if self.revision != expected {
            return Err(AuthorityError::Conflict);
        }
        require(matches!(
            self.state,
            OrganizationState::Active | OrganizationState::Suspended
        ))?;
        let revision = increment(self.revision, false)?;
        let generation = increment(self.grant_generation, false)?;
        self.revision = revision;
        self.grant_generation = generation;
        self.state = OrganizationState::Provisioning;
        Ok(())
    }

    /// Last-administrator and caller-policy checks belong to the same locked
    /// repository transaction as this state transition.
    pub fn transition(
        &mut self,
        expected_revision: i64,
        next: OrganizationState,
    ) -> Result<(), AuthorityError> {
        self.validate()?;
        if self.revision != expected_revision {
            return Err(AuthorityError::Conflict);
        }
        let allowed = matches!(
            (self.state, next),
            (OrganizationState::Provisioning, OrganizationState::Active)
                | (OrganizationState::Provisioning, OrganizationState::Deleted)
                | (OrganizationState::Active, OrganizationState::Suspended)
                | (OrganizationState::Active, OrganizationState::Deleted)
                | (OrganizationState::Suspended, OrganizationState::Active)
                | (OrganizationState::Suspended, OrganizationState::Deleted)
        );
        if !allowed {
            return Err(AuthorityError::Forbidden);
        }
        let revision = increment(self.revision, next == OrganizationState::Deleted)?;
        let generation = if next == OrganizationState::Active {
            increment(self.grant_generation, false)?
        } else {
            self.grant_generation
        };
        self.revision = revision;
        self.grant_generation = generation;
        self.state = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum MembershipState {
    Invited,
    Active,
    Suspended,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Membership {
    pub scope: Scope,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub incarnation: Uuid,
    pub state: MembershipState,
    pub revision: i64,
    pub grant_generation: i64,
    pub roles: BTreeSet<String>,
}

impl Membership {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.scope.validate()?;
        require(
            !self.organization_id.is_nil()
                && !self.user_id.is_nil()
                && !self.incarnation.is_nil()
                && self.revision > 0
                && self.grant_generation > 0
                && valid_keys(&self.roles, MAX_ROLES),
        )
    }

    /// Only a separately authorized rejoin operation may replace a removed
    /// membership. Invitation acceptance cannot call this to restore authority.
    pub fn update(
        &mut self,
        expected_revision: i64,
        state: MembershipState,
        roles: BTreeSet<String>,
    ) -> Result<(), AuthorityError> {
        self.validate()?;
        require(valid_keys(&roles, MAX_ROLES))?;
        if self.revision != expected_revision {
            return Err(AuthorityError::Conflict);
        }
        if self.state == MembershipState::Removed
            || state == MembershipState::Invited
            || (self.state == MembershipState::Invited && state == MembershipState::Suspended)
        {
            return Err(AuthorityError::Forbidden);
        }
        if self.state == state && self.roles == roles {
            return Ok(());
        }
        let revision = increment(self.revision, state == MembershipState::Removed)?;
        let broadens = state == MembershipState::Active
            && (self.state != MembershipState::Active || !roles.is_subset(&self.roles));
        let generation = if broadens {
            increment(self.grant_generation, false)?
        } else {
            self.grant_generation
        };
        self.revision = revision;
        self.grant_generation = generation;
        self.roles = roles;
        self.state = state;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDefinition {
    pub scope: Scope,
    pub key: String,
    pub version: i64,
    pub privileges: BTreeSet<String>,
    pub manages_members: bool,
    pub assignable_roles: BTreeSet<String>,
}

impl RoleDefinition {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.scope.validate()?;
        require(
            valid_key(&self.key)
                && self.version > 0
                && !self.privileges.is_empty()
                && valid_keys(&self.privileges, MAX_PRIVILEGES)
                && valid_keys(&self.assignable_roles, MAX_ROLES)
                && (self.manages_members || self.assignable_roles.is_empty()),
        )
    }
}

pub(super) fn roles_for<'a>(
    member: &Membership,
    definitions: &'a BTreeMap<String, RoleDefinition>,
) -> Result<Vec<&'a RoleDefinition>, AuthorityError> {
    member
        .roles
        .iter()
        .map(|key| {
            let role = definitions.get(key).ok_or(AuthorityError::Invalid)?;
            role.validate()?;
            require(role.scope == member.scope && &role.key == key)?;
            Ok(role)
        })
        .collect()
}

pub(super) fn increment(value: i64, terminal: bool) -> Result<i64, AuthorityError> {
    aegaeon_pure::organization_bounds::next_revision(value, terminal)
        .ok_or(AuthorityError::Exhausted)
}

pub(super) fn require(condition: bool) -> Result<(), AuthorityError> {
    if condition {
        Ok(())
    } else {
        Err(AuthorityError::Invalid)
    }
}

pub(super) fn valid_external_id(value: &str) -> bool {
    (1..=256).contains(&value.len()) && !value.chars().any(char::is_control)
}

pub(super) fn valid_key(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
}

pub(super) fn valid_keys(values: &BTreeSet<String>, limit: usize) -> bool {
    values.len() <= limit && values.iter().all(|value| valid_key(value))
}
