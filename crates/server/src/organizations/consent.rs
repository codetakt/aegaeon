//! Server-only original approval. Public RAR data is a request, never a credential.
use super::model::{require, valid_external_id, valid_keys, MAX_PRIVILEGES};
use super::{AuthorityError, AuthorizationCeiling, Binding, MembershipCeiling, Scope};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

mod capture;
pub(crate) use capture::{capture, client, CaptureContext};

pub const GRANT_TYPE: &str = "https://github.com/codetakt/aegaeon/spec/organization-grant/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantRequest {
    #[serde(rename = "type")]
    pub detail_type: String,
    pub locations: Vec<String>,
    pub organizations: Vec<Selection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub identifier: String,
    pub privileges: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub administrative_access: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl GrantRequest {
    pub fn parse(value: &serde_json::Value) -> Result<Self, AuthorityError> {
        let bytes = serde_json::to_vec(value).map_err(|_| AuthorityError::Invalid)?;
        require(bytes.len() <= 16 * 1024)?;
        let [detail] = value.as_array().ok_or(AuthorityError::Invalid)?.as_slice() else {
            return Err(AuthorityError::Invalid);
        };
        let request: Self =
            serde_json::from_value(detail.clone()).map_err(|_| AuthorityError::Invalid)?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), AuthorityError> {
        require(
            serde_json::to_vec(&[self])
                .map_err(|_| AuthorityError::Invalid)?
                .len()
                <= 16 * 1024,
        )?;
        require(self.detail_type == GRANT_TYPE && self.locations.len() == 1)?;
        let audience = &self.locations[0];
        require(
            !audience.is_empty()
                && audience.len() <= 2048
                && !audience.chars().any(char::is_control),
        )?;
        require(!self.organizations.is_empty() && self.organizations.len() <= 16)?;
        let mut ids = BTreeSet::new();
        let mut all_privileges = BTreeSet::new();
        for selection in &self.organizations {
            let privileges: BTreeSet<_> = selection.privileges.iter().cloned().collect();
            require(
                valid_external_id(&selection.identifier)
                    && ids.insert(&selection.identifier)
                    && !privileges.is_empty()
                    && privileges.len() == selection.privileges.len()
                    && valid_keys(&privileges, MAX_PRIVILEGES),
            )?;
            all_privileges.extend(privileges);
        }
        require(all_privileges.len() <= MAX_PRIVILEGES)?;
        Ok(())
    }
}

/// Original support permission, separate from membership and from an activated grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupportCeiling {
    pub organization_generation: i64,
    pub policy_revision: i64,
    pub administrator_id: Uuid,
    pub operator_grant_id: Uuid,
    pub operator_revision: i64,
    pub role_versions: BTreeMap<String, i64>,
    pub privileges: BTreeSet<String>,
}

/// Captured before display, rechecked on approval, and bound to a root by the issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Consent {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<super::witness::epoch::EpochBinding>,
    pub request: GrantRequest,
    pub scope: Scope,
    pub issuer: String,
    pub client_id: String,
    pub client_registration_id: Uuid,
    pub client_binding_id: Uuid,
    pub client_binding_revision: i64,
    pub domain_revision: i64,
    pub subject: String,
    pub user_id: Uuid,
    pub identity_revision: i64,
    pub dpop_jkt: String,
    pub auth_time: i64,
    pub captured_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_authentication: Option<super::authentication::OriginalAuthentication>,
    pub memberships: BTreeMap<Uuid, MembershipCeiling>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub support: BTreeMap<Uuid, SupportCeiling>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootAuthority {
    pub consent: Consent,
    pub ceiling: AuthorizationCeiling,
}

impl Consent {
    fn valid_epoch_shape(&self) -> bool {
        self.version == 2
            && self
                .epoch
                .as_ref()
                .is_some_and(|epoch| epoch.environment_id() == self.scope.environment_id)
    }

    pub(crate) fn require_current_epoch(&self) -> Result<(), AuthorityError> {
        let owner = super::request_work::async_store::current_owner()
            .map_err(|_| AuthorityError::Forbidden)?;
        require(
            self.version == 2
                && self.epoch.as_ref().is_some_and(|epoch| {
                    epoch.environment_id() == self.scope.environment_id
                        && epoch.matches_owner(&owner)
                }),
        )
    }

    pub fn bind(&self, root_id: &str, expires_at: i64) -> Result<RootAuthority, AuthorityError> {
        require(self.valid_epoch_shape())?;
        Ok(RootAuthority {
            consent: self.clone(),
            ceiling: self.reconstruct_ceiling(root_id, expires_at)?,
        })
    }

    /// Custody validation only: no new root is returned and no current authority is implied.
    pub(super) fn validate_history(
        &self,
        ceiling: &AuthorizationCeiling,
    ) -> Result<(), AuthorityError> {
        require((self.version == 1 && self.epoch.is_none()) || self.valid_epoch_shape())?;
        require(self.reconstruct_ceiling(&ceiling.binding.root_id, ceiling.expires_at)? == *ceiling)
    }

    fn reconstruct_ceiling(
        &self,
        root_id: &str,
        expires_at: i64,
    ) -> Result<AuthorizationCeiling, AuthorityError> {
        self.request.validate()?;
        require(crate::authcode::types::DpopKeyThumbprint::parse(&self.dpop_jkt).is_ok())?;
        require(
            self.domain_revision > 0
                && self.client_binding_revision > 0
                && !self.client_binding_id.is_nil()
                && (1..i64::MAX).contains(&self.identity_revision)
                && self.auth_time > 0
                && self.auth_time <= self.captured_at
                && self.memberships.len() + self.support.len() == self.request.organizations.len()
                && self.support.len()
                    == self
                        .request
                        .organizations
                        .iter()
                        .filter(|s| s.administrative_access)
                        .count(),
        )?;
        if let Some(evidence) = &self.original_authentication {
            require(
                evidence.matches_session(&self.subject, self.auth_time, self.captured_at)
                    && evidence.matches_identity(
                        self.scope.environment_id,
                        self.user_id,
                        self.identity_revision,
                    ),
            )?;
        }
        if !self.support.is_empty() {
            let evidence = self
                .original_authentication
                .as_ref()
                .ok_or(AuthorityError::Forbidden)?;
            require(
                self.captured_at >= evidence.auth_time
                    && self.captured_at - evidence.auth_time < 300,
            )?;
        }
        for (id, support) in &self.support {
            require(
                !id.is_nil()
                    && !self.memberships.contains_key(id)
                    && !support.administrator_id.is_nil()
                    && !support.operator_grant_id.is_nil()
                    && (1..i64::MAX).contains(&support.organization_generation)
                    && (1..i64::MAX).contains(&support.policy_revision)
                    && (1..i64::MAX).contains(&support.operator_revision)
                    && !support.role_versions.is_empty()
                    && support.role_versions.len() <= super::MAX_ROLES
                    && support
                        .role_versions
                        .iter()
                        .all(|(k, v)| super::model::valid_key(k) && (1..i64::MAX).contains(v))
                    && !support.privileges.is_empty()
                    && valid_keys(&support.privileges, MAX_PRIVILEGES),
            )?;
        }
        let ceiling = AuthorizationCeiling {
            version: 1,
            binding: Binding {
                scope: self.scope,
                issuer: self.issuer.clone(),
                client_id: self.client_id.clone(),
                client_registration_id: self.client_registration_id,
                subject: self.subject.clone(),
                user_id: self.user_id,
                root_id: root_id.into(),
                dpop_jkt: self.dpop_jkt.clone(),
            },
            expires_at: expires_at.min(
                self.captured_at
                    .checked_add(86400)
                    .ok_or(AuthorityError::Exhausted)?,
            ),
            audiences: BTreeMap::from([(
                self.request.locations[0].clone(),
                self.request
                    .organizations
                    .iter()
                    .flat_map(|s| s.privileges.iter().cloned())
                    .collect(),
            )]),
            memberships: self.memberships.clone(),
        };
        require(ceiling.expires_at > self.captured_at)?;
        ceiling.validate()?;
        require(
            serde_json::to_vec(self)
                .map_err(|_| AuthorityError::Invalid)?
                .len()
                <= 64 * 1024,
        )?;
        Ok(ceiling)
    }
}
