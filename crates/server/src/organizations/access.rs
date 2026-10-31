use super::model::{require, roles_for, valid_external_id, valid_key, valid_keys, MAX_PRIVILEGES};
use super::{
    AuthorityError, Membership, MembershipState, Organization, OrganizationState, RoleDefinition,
    Scope, ORGANIZATION_ACCESS_TYPE,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Authority bindings obtained from authenticated server state. Never accept a
/// serialized binding, ceiling or snapshot as a caller-provided credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub scope: Scope,
    pub issuer: String,
    pub client_id: String,
    pub client_registration_id: Uuid,
    pub subject: String,
    pub user_id: Uuid,
    pub root_id: String,
    pub dpop_jkt: String,
}

impl Binding {
    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
        self.scope.validate()?;
        require(!self.user_id.is_nil() && !self.client_registration_id.is_nil())?;
        for value in [
            &self.issuer,
            &self.client_id,
            &self.subject,
            &self.root_id,
            &self.dpop_jkt,
        ] {
            require(
                !value.is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCeiling {
    pub organization_generation: i64,
    pub incarnation: Uuid,
    pub grant_generation: i64,
    pub role_versions: BTreeMap<String, i64>,
    pub privileges: BTreeSet<String>,
}

/// Captured during original authorization, before publication of its root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationCeiling {
    pub version: u32,
    pub binding: Binding,
    pub expires_at: i64,
    pub audiences: BTreeMap<String, BTreeSet<String>>,
    pub memberships: BTreeMap<Uuid, MembershipCeiling>,
}

impl AuthorizationCeiling {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.binding.validate()?;
        require(
            self.version == 1
                && self.expires_at > 0
                && !self.audiences.is_empty()
                && self.audiences.len() <= 32
                && self.memberships.len() <= 256,
        )?;
        for (audience, privileges) in &self.audiences {
            require(
                !audience.is_empty()
                    && audience.len() <= 2048
                    && !audience.chars().any(char::is_control)
                    && !privileges.is_empty()
                    && valid_keys(privileges, MAX_PRIVILEGES),
            )?;
        }
        for (id, member) in &self.memberships {
            require(
                !id.is_nil()
                    && !member.incarnation.is_nil()
                    && member.organization_generation > 0
                    && member.grant_generation > 0
                    && member.role_versions.len() <= super::MAX_ROLES
                    && member
                        .role_versions
                        .iter()
                        .all(|(key, version)| valid_key(key) && *version > 0)
                    && !member.privileges.is_empty()
                    && valid_keys(&member.privileges, MAX_PRIVILEGES),
            )?;
        }
        Ok(())
    }

    pub fn capture_membership(
        organization: &Organization,
        member: &Membership,
        definitions: &BTreeMap<String, RoleDefinition>,
    ) -> Result<MembershipCeiling, AuthorityError> {
        active_membership(organization, member)?;
        let roles = roles_for(member, definitions)?;
        let privileges: BTreeSet<String> = roles
            .iter()
            .flat_map(|role| role.privileges.iter().cloned())
            .collect();
        require(!privileges.is_empty() && valid_keys(&privileges, MAX_PRIVILEGES))?;
        let role_versions = roles
            .iter()
            .map(|role| (role.key.clone(), role.version))
            .collect();
        Ok(MembershipCeiling {
            organization_generation: organization.grant_generation,
            incarnation: member.incarnation,
            grant_generation: member.grant_generation,
            role_versions,
            privileges,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRequest {
    #[serde(rename = "type")]
    pub detail_type: String,
    pub identifier: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_admin_grant"
    )]
    pub admin_access_grant_id: Option<Uuid>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_privileges"
    )]
    pub privileges: Option<Vec<String>>,
}

fn present_admin_grant<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Uuid>, D::Error> {
    let text = String::deserialize(deserializer)?;
    let id = Uuid::parse_str(&text).map_err(serde::de::Error::custom)?;
    if text != id.to_string() {
        return Err(serde::de::Error::custom("canonical UUID required"));
    }
    Ok(Some(id))
}

fn present_privileges<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(deserializer).map(Some)
}

impl AccessRequest {
    pub fn parse(json: &str) -> Result<Self, AuthorityError> {
        require(json.len() <= 65536)?;
        let mut details: Vec<Self> =
            serde_json::from_str(json).map_err(|_| AuthorityError::Invalid)?;
        require(details.len() == 1)?;
        let request = details.pop().ok_or(AuthorityError::Invalid)?;
        request.validate()?;
        Ok(request)
    }

    /// Validate the external selector without interpreting it as an internal ID.
    /// Resolution requires authoritative Environment and target-domain state.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        require(
            self.detail_type == ORGANIZATION_ACCESS_TYPE
                && valid_external_id(&self.identifier)
                && self.admin_access_grant_id.is_none_or(|id| !id.is_nil()),
        )?;
        if let Some(values) = &self.privileges {
            let unique: BTreeSet<_> = values.iter().cloned().collect();
            require(
                !values.is_empty()
                    && unique.len() == values.len()
                    && valid_keys(&unique, MAX_PRIVILEGES),
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "access_basis", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessAuthority {
    Membership {
        revision: i64,
        generation: i64,
        incarnation: Uuid,
    },
    AdministrativeGrant {
        grant_id: Uuid,
        grant_revision: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessDecision {
    pub binding: Binding,
    pub organization_id: Uuid,
    /// Exact external identifier from the authoritative organization row.
    /// Required on deserialization: old UUID-derived snapshots cannot infer it.
    pub organization_identifier: String,
    pub audience: String,
    pub privileges: BTreeSet<String>,
    pub organization_revision: i64,
    pub organization_generation: i64,
    pub authority: AccessAuthority,
    pub role_versions: BTreeMap<String, i64>,
    pub expires_at: i64,
}

#[derive(Clone, Copy)]
pub struct AccessInput<'a> {
    pub ceiling: &'a AuthorizationCeiling,
    pub authenticated: &'a Binding,
    pub request: &'a AccessRequest,
    pub audience: &'a str,
    pub current_client_privileges: &'a BTreeSet<String>,
    pub organization: &'a Organization,
    pub member: &'a Membership,
    pub definitions: &'a BTreeMap<String, RoleDefinition>,
    pub parent_expires_at: i64,
    pub now: i64,
}

impl AccessDecision {
    /// All inputs must come from one authoritative read snapshot. The caller
    /// separately validates current OAuth client/target policy and root liveness.
    pub fn authorize(input: AccessInput<'_>) -> Result<Self, AuthorityError> {
        let AccessInput {
            ceiling,
            authenticated,
            request,
            audience,
            current_client_privileges,
            organization,
            member,
            definitions,
            parent_expires_at,
            now,
        } = input;
        require(request.admin_access_grant_id.is_none())?;
        ceiling.validate()?;
        request.validate()?;
        active_membership(organization, member)?;
        if &ceiling.binding != authenticated
            || member.user_id != authenticated.user_id
            || member.scope != authenticated.scope
            || request.identifier != organization.external_id
        {
            return Err(AuthorityError::Forbidden);
        }
        let original = ceiling
            .memberships
            .get(&organization.id)
            .ok_or(AuthorityError::ReauthorizationRequired)?;
        if (
            original.incarnation,
            original.grant_generation,
            original.organization_generation,
        ) != (
            member.incarnation,
            member.grant_generation,
            organization.grant_generation,
        ) {
            return Err(AuthorityError::ReauthorizationRequired);
        }
        let target = ceiling
            .audiences
            .get(audience)
            .ok_or(AuthorityError::Forbidden)?;
        require(valid_keys(current_client_privileges, MAX_PRIVILEGES))?;
        let roles = roles_for(member, definitions)?;
        for role in &roles {
            if original.role_versions.get(&role.key) != Some(&role.version) {
                return Err(AuthorityError::ReauthorizationRequired);
            }
        }
        let current: BTreeSet<_> = roles
            .iter()
            .flat_map(|role| role.privileges.iter().cloned())
            .collect();
        let allowed: BTreeSet<String> = original
            .privileges
            .intersection(&current)
            .filter(|key| target.contains(*key) && current_client_privileges.contains(*key))
            .cloned()
            .collect();
        let privileges = select_privileges(request, allowed)?;
        let expires_at = aegaeon_pure::organization_bounds::selected_expiry(
            ceiling.expires_at,
            parent_expires_at,
            now,
        )
        .map_err(|error| match error {
            aegaeon_pure::organization_bounds::LifetimeError::Overflow => AuthorityError::Invalid,
            aegaeon_pure::organization_bounds::LifetimeError::NotLive => AuthorityError::Forbidden,
        })?;
        Ok(Self {
            binding: authenticated.clone(),
            organization_id: organization.id,
            organization_identifier: organization.external_id.clone(),
            audience: audience.into(),
            privileges,
            organization_revision: organization.revision,
            organization_generation: organization.grant_generation,
            authority: AccessAuthority::Membership {
                revision: member.revision,
                generation: member.grant_generation,
                incarnation: member.incarnation,
            },
            role_versions: roles
                .into_iter()
                .map(|role| (role.key.clone(), role.version))
                .collect(),
            expires_at,
        })
    }

    /// Online resource check, after token/root/target authentication. Changes in
    /// any selected authority invalidate the issued token, including demotions.
    pub fn is_current(
        &self,
        organization: &Organization,
        member: &Membership,
        definitions: &BTreeMap<String, RoleDefinition>,
        now: i64,
    ) -> bool {
        if self.binding.validate().is_err()
            || active_membership(organization, member).is_err()
            || now < 0
            || now >= self.expires_at
            || self.privileges.is_empty()
            || !valid_keys(&self.privileges, MAX_PRIVILEGES)
            || self.binding.scope != member.scope
            || self.binding.user_id != member.user_id
            || self.organization_id != organization.id
            || self.organization_identifier != organization.external_id
            || self.organization_revision != organization.revision
            || self.organization_generation != organization.grant_generation
            || self.authority
                != (AccessAuthority::Membership {
                    revision: member.revision,
                    generation: member.grant_generation,
                    incarnation: member.incarnation,
                })
        {
            return false;
        }
        let Ok(roles) = roles_for(member, definitions) else {
            return false;
        };
        let versions: BTreeMap<_, _> = roles
            .iter()
            .map(|role| (role.key.clone(), role.version))
            .collect();
        let privileges: BTreeSet<_> = roles
            .iter()
            .flat_map(|role| role.privileges.iter().cloned())
            .collect();
        versions == self.role_versions && self.privileges.is_subset(&privileges)
    }

    pub fn authorization_details(&self) -> serde_json::Value {
        let mut detail = serde_json::json!({"type":ORGANIZATION_ACCESS_TYPE,"identifier":self.organization_identifier,"privileges":self.privileges,"access_basis":"membership"});
        if let AccessAuthority::AdministrativeGrant { grant_id, .. } = &self.authority {
            detail["access_basis"] = serde_json::json!("administrative_grant");
            detail["admin_access_grant_id"] = serde_json::json!(grant_id);
        }
        serde_json::json!([detail])
    }
}

pub(super) fn select_privileges(
    request: &AccessRequest,
    allowed: BTreeSet<String>,
) -> Result<BTreeSet<String>, AuthorityError> {
    let privileges = if let Some(values) = &request.privileges {
        let requested: BTreeSet<String> = values.iter().cloned().collect();
        require(
            !requested.is_empty()
                && values.len() == requested.len()
                && valid_keys(&requested, MAX_PRIVILEGES),
        )?;
        if !requested.is_subset(&allowed) {
            return Err(AuthorityError::Forbidden);
        }
        requested
    } else {
        allowed
    };
    if privileges.is_empty() {
        return Err(AuthorityError::Forbidden);
    }
    Ok(privileges)
}

fn active_membership(
    organization: &Organization,
    member: &Membership,
) -> Result<(), AuthorityError> {
    organization.validate()?;
    member.validate()?;
    if (organization.scope, organization.id) != (member.scope, member.organization_id) {
        return Err(AuthorityError::Forbidden);
    }
    if organization.state != OrganizationState::Active || member.state != MembershipState::Active {
        return Err(AuthorityError::Forbidden);
    }
    Ok(())
}
