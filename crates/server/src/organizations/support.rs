//! Explicit temporary operator authority; never represented as a membership.
use super::{
    consent::{RootAuthority, SupportCeiling},
    model::{require, valid_keys, MAX_PRIVILEGES},
    repository::{self as repo, RepositoryError},
    *,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
mod current;
mod mutations;
mod storage;
pub(crate) use current::authorize;
pub(crate) use mutations::{activate, revoke, Activation, Revoke};
pub(crate) use storage::read;

pub(crate) const MAX_GRANTS: i64 = 10_000;
pub(crate) const PRIVILEGE: &str = "organization.support.activate";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authority {
    pub binding: Binding,
    pub ceiling: SupportCeiling,
    pub audience: String,
    pub organization_id: Uuid,
    pub organization_revision: i64,
    pub auth_time: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Grant {
    pub id: Uuid,
    pub authority: Authority,
    pub revision: i64,
    pub active: bool,
    pub issued_at: i64,
    pub expires_at: i64,
}

pub(crate) struct Context<'a> {
    pub original: &'a RootAuthority,
    pub binding: &'a Binding,
    pub parent_expires_at: i64,
    pub now: i64,
}

impl Grant {
    pub(in crate::organizations) fn validate(&self) -> Result<(), AuthorityError> {
        self.authority.binding.validate()?;
        require(
            !self.authority.audience.is_empty()
                && self.authority.audience.len() <= 2048
                && !self.authority.audience.chars().any(char::is_control),
        )?;
        let c = &self.authority.ceiling;
        require(
            !self.id.is_nil()
                && !self.authority.organization_id.is_nil()
                && self.revision > 0
                && self.issued_at > 0
                && self.expires_at > self.issued_at
                && self.expires_at - self.issued_at <= 300
                && self.authority.auth_time > 0
                && self.issued_at >= self.authority.auth_time
                && self.expires_at
                    <= self
                        .authority
                        .auth_time
                        .checked_add(300)
                        .ok_or(AuthorityError::Exhausted)?
                && (1..i64::MAX).contains(&self.authority.organization_revision)
                && (1..i64::MAX).contains(&c.organization_generation)
                && (1..i64::MAX).contains(&c.policy_revision)
                && (1..i64::MAX).contains(&c.operator_revision)
                && !c.administrator_id.is_nil()
                && !c.operator_grant_id.is_nil()
                && !c.role_versions.is_empty()
                && c.role_versions.len() <= MAX_ROLES
                && c.role_versions
                    .iter()
                    .all(|(k, v)| super::model::valid_key(k) && (1..i64::MAX).contains(v))
                && !c.privileges.is_empty()
                && valid_keys(&c.privileges, MAX_PRIVILEGES),
        )
    }
    fn require_live(&self, now: i64) -> Result<(), AuthorityError> {
        self.validate()?;
        if !self.active || now < self.issued_at || now >= self.expires_at {
            return Err(AuthorityError::Forbidden);
        }
        Ok(())
    }
}
