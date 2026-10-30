use super::{AccessDecision, AuthorityError, Binding, Membership, Organization, RoleDefinition};
use std::collections::{BTreeMap, BTreeSet};

pub const MANAGE_MEMBERS: &str = "organization.members.manage";

#[derive(Clone, Copy)]
pub struct DelegationInput<'a> {
    pub access: &'a AccessDecision,
    pub authenticated: &'a Binding,
    /// Resolved from the registered domain target, not a request parameter.
    pub management_audience: &'a str,
    pub current_client_privileges: &'a BTreeSet<String>,
    pub organization: &'a Organization,
    pub actor_membership: &'a Membership,
    pub definitions: &'a BTreeMap<String, RoleDefinition>,
    pub assign_roles: &'a BTreeSet<String>,
    pub now: i64,
}

/// The HTTP boundary must validate the token/root and DPoP before calling this.
/// Unlike exchange, delegation uses the issued token's exact current versions.
pub fn authorize_membership_change(input: &DelegationInput<'_>) -> Result<(), AuthorityError> {
    if &input.access.binding != input.authenticated
        || input.access.audience != input.management_audience
        || !input.access.privileges.contains(MANAGE_MEMBERS)
        || !input.current_client_privileges.contains(MANAGE_MEMBERS)
        || !input.access.is_current(
            input.organization,
            input.actor_membership,
            input.definitions,
            input.now,
        )
    {
        return Err(AuthorityError::Forbidden);
    }
    let roles = super::model::roles_for(input.actor_membership, input.definitions)?;
    let administrative: Vec<_> = roles.iter().filter(|role| role.manages_members).collect();
    let assignable: BTreeSet<_> = administrative
        .iter()
        .flat_map(|role| role.assignable_roles.iter().cloned())
        .collect();
    if administrative.is_empty()
        || !input.assign_roles.is_subset(&assignable)
        || input
            .assign_roles
            .iter()
            .any(|key| !input.definitions.contains_key(key))
    {
        return Err(AuthorityError::Forbidden);
    }
    Ok(())
}
