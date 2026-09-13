//! The explicit Inorii application contract, separate from OAuth/OIDC claims.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

pub const CLAIM_NAME: &str = "https://inorii.com/claims";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = ApplicationGlobalRole))]
pub enum GlobalRole {
    User,
    SuperAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = ApplicationOrganizationRole))]
pub enum OrganizationRole {
    OrganizationAdmin,
    OrganizationStaff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = ApplicationOrganizationGrant))]
pub struct OrganizationGrant {
    pub organization_id: String,
    pub roles: Vec<OrganizationRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = ApplicationAuthorizationClaims))]
pub struct Claims {
    pub roles: Vec<GlobalRole>,
    #[serde(default)]
    pub organization_roles: Vec<OrganizationGrant>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid application authorization")]
pub struct InvalidAuthorization;

/// Strictly canonical identifiers; no aliases or caller-controlled normalization.
#[must_use]
pub fn valid_organization_id(value: &str) -> bool {
    value
        .strip_prefix("organization_")
        .is_some_and(|suffix| Uuid::parse_str(suffix).is_ok_and(|id| id.to_string() == suffix))
}

impl Claims {
    pub fn validate(&self) -> Result<(), InvalidAuthorization> {
        if !unique(&self.roles)
            || self.organization_roles.len() > 256
            || self
                .organization_roles
                .iter()
                .map(|grant| &grant.organization_id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.organization_roles.len()
            || self.organization_roles.iter().any(|grant| {
                !valid_organization_id(&grant.organization_id)
                    || grant.roles.is_empty()
                    || !unique(&grant.roles)
            })
        {
            return Err(InvalidAuthorization);
        }
        Ok(())
    }

    /// Select only previously granted membership. A global role never invents a membership.
    /// Remove global administrative authority so consumers cannot bypass this boundary.
    pub fn select(&self, organization: &str) -> Result<Self, InvalidAuthorization> {
        self.validate()?;
        if !valid_organization_id(organization) {
            return Err(InvalidAuthorization);
        }
        let grant = self
            .organization_roles
            .iter()
            .find(|grant| grant.organization_id == organization)
            .ok_or(InvalidAuthorization)?;
        Ok(Self {
            roles: self
                .roles
                .iter()
                .copied()
                .filter(|role| *role != GlobalRole::SuperAdmin)
                .collect(),
            organization_roles: vec![grant.clone()],
        })
    }

    #[must_use]
    pub fn is_restriction_of(&self, parent: &Self) -> bool {
        self.validate().is_ok()
            && parent.validate().is_ok()
            && self.roles.iter().all(|role| parent.roles.contains(role))
            && self.organization_roles.iter().all(|grant| {
                parent.organization_roles.iter().any(|prior| {
                    prior.organization_id == grant.organization_id
                        && grant.roles.iter().all(|role| prior.roles.contains(role))
                })
            })
    }
}

fn unique<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

/// Captured from the privileged application projection, never from a profile or request.
/// A changed projection revision invalidates the grant; it cannot upgrade an old authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub version: u32,
    pub environment_id: Uuid,
    pub issuer: String,
    pub client_id: String,
    pub subject: String,
    pub revision: i64,
    pub audiences: Vec<String>,
    pub selected_organization: Option<String>,
    pub claims: Claims,
}

impl Grant {
    pub fn validate(&self) -> Result<(), InvalidAuthorization> {
        self.claims.validate()?;
        if self.version != 1
            || self.revision < 1
            || self.environment_id.is_nil()
            || self.issuer.is_empty()
            || self.client_id.is_empty()
            || self.subject.is_empty()
            || (self.client_id == self.subject
                && (!self.claims.roles.is_empty() || !self.claims.organization_roles.is_empty()))
            || self.audiences.is_empty()
            || self.audiences.len() > 32
            || !unique(&self.audiences)
            || self
                .audiences
                .iter()
                .any(|aud| aud.is_empty() || aud.len() > 2048)
            || self
                .selected_organization
                .as_ref()
                .is_some_and(|organization| {
                    self.claims.select(organization).as_ref() != Ok(&self.claims)
                })
        {
            return Err(InvalidAuthorization);
        }
        Ok(())
    }

    pub fn restrict(
        &self,
        audience: &str,
        organization: Option<&str>,
    ) -> Result<Self, InvalidAuthorization> {
        self.validate()?;
        if !self.audiences.iter().any(|aud| aud == audience)
            || self
                .selected_organization
                .as_deref()
                .is_some_and(|prior| organization.is_some_and(|requested| requested != prior))
        {
            return Err(InvalidAuthorization);
        }
        let mut output = self.clone();
        output.audiences = vec![audience.to_owned()];
        if let Some(organization) = organization {
            output.claims = self.claims.select(organization)?;
            output.selected_organization = Some(organization.to_owned());
        }
        output.validate()?;
        Ok(output)
    }

    #[must_use]
    pub fn is_restriction_of(&self, parent: &Self) -> bool {
        self.validate().is_ok()
            && parent.validate().is_ok()
            && self.environment_id == parent.environment_id
            && self.issuer == parent.issuer
            && self.client_id == parent.client_id
            && self.subject == parent.subject
            && self.revision == parent.revision
            && self
                .audiences
                .iter()
                .all(|aud| parent.audiences.contains(aud))
            && parent
                .selected_organization
                .as_ref()
                .is_none_or(|prior| self.selected_organization.as_ref() == Some(prior))
            && self.claims.is_restriction_of(&parent.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims() -> Claims {
        serde_json::from_value(json!({
            "roles": ["USER", "SUPER_ADMIN"],
            "organization_roles": [
                {"organization_id": "organization_00000000-0000-4000-8000-000000000001", "roles": ["ORGANIZATION_ADMIN"]},
                {"organization_id": "organization_00000000-0000-4000-8000-000000000002", "roles": ["ORGANIZATION_STAFF"]}
            ]
        })).unwrap()
    }

    #[test]
    fn rejects_unknown_roles_fields_duplicate_and_noncanonical_memberships() {
        for value in [
            json!({"roles":["admin"]}),
            json!({"roles":["USER"],"extra":true}),
            json!({"roles":["USER", "USER"]}),
            json!({"roles":[],"organization_roles":[{"organization_id":"1","roles":["ORGANIZATION_ADMIN"]}]}),
        ] {
            assert!(serde_json::from_value::<Claims>(value)
                .map_or(true, |claims| claims.validate().is_err()));
        }
        let mut duplicate = claims();
        duplicate
            .organization_roles
            .push(duplicate.organization_roles[0].clone());
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn selection_drops_global_override_and_cannot_invent_or_switch_membership() {
        let parent = Grant {
            version: 1,
            environment_id: Uuid::new_v4(),
            issuer: "https://issuer.invalid".into(),
            client_id: "bff".into(),
            subject: "subject".into(),
            revision: 7,
            audiences: vec!["service-a".into(), "service-b".into()],
            selected_organization: None,
            claims: claims(),
        };
        let org = &parent.claims.organization_roles[0].organization_id;
        let narrowed = parent.restrict("service-a", Some(org)).unwrap();
        assert!(narrowed.is_restriction_of(&parent));
        assert_eq!(narrowed.claims.roles, vec![GlobalRole::User]);
        assert_eq!(narrowed.claims.organization_roles.len(), 1);
        assert!(narrowed.restrict("service-b", None).is_err());
        assert!(narrowed
            .restrict(
                "service-a",
                Some(&parent.claims.organization_roles[1].organization_id)
            )
            .is_err());
        assert!(parent
            .restrict(
                "service-a",
                Some("organization_00000000-0000-4000-8000-000000000003")
            )
            .is_err());
        let mut changed = narrowed.clone();
        changed.revision += 1;
        assert!(!changed.is_restriction_of(&parent));
        assert!(!parent.is_restriction_of(&narrowed));
        assert_eq!(
            narrowed,
            serde_json::from_value::<Grant>(serde_json::to_value(&narrowed).unwrap()).unwrap()
        );
    }
}
