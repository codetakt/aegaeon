//! Native organization authority. This module does not infer authority from
//! editable profile claims, external organization names or operator sessions.
//!
//! The protocol integration must authenticate its caller and bind the original
//! authorization before using these values. A deserialized snapshot is not a
//! credential. See docs/design/organizations for activation dependencies.

mod access;
pub(crate) mod audit;
pub(crate) mod authentication;
pub mod commands;
pub(crate) mod consent;
pub mod delegation;
pub mod http_input;
pub(crate) mod identity;
pub mod invitation_capabilities;
pub mod invitations;
mod model;
pub mod operators;
pub mod repository;
pub mod request_work;
pub(crate) mod selected;
pub mod snapshot;
pub(crate) mod support;

pub use access::{
    AccessAuthority, AccessDecision, AccessInput, AccessRequest, AuthorizationCeiling, Binding,
    MembershipCeiling,
};
pub use model::{
    AuthorityError, Membership, MembershipState, Organization, OrganizationState, RoleDefinition,
    Scope, MAX_ROLES, ORGANIZATION_ACCESS_TYPE,
};

#[cfg(test)]
pub(crate) mod repository_tests;
#[cfg(test)]
mod tests;
