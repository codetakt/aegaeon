//! Selected authority snapshot. Token authentication and root liveness are caller obligations.
use super::{consent::RootAuthority, model::require, repository as repo, *};
use repo::RepositoryError;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeSet;

mod current;
mod metadata;
mod primary;
pub(crate) use current::{is_current, recipient_current};
pub(crate) use primary::{current_client, lock_primary_scope};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectedAuthority {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<super::witness::epoch::EpochBinding>,
    pub issued_at: i64,
    pub parent_expires_at: i64,
    pub decision: AccessDecision,
    pub domain_revision: i64,
    pub client_binding_id: uuid::Uuid,
    pub client_binding_revision: i64,
}

pub(crate) struct SelectionInput<'a> {
    pub original: &'a RootAuthority,
    pub authenticated: &'a Binding,
    pub request: &'a AccessRequest,
    pub audience: &'a str,
    pub parent_expires_at: i64,
    pub now: i64,
}

pub(crate) async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    input: SelectionInput<'_>,
) -> Result<SelectedAuthority, RepositoryError> {
    validate_original(input.original, input.authenticated, input.now)?;
    let client = primary::current_client(tx, input.original, input.audience).await?;
    let organization = repo::resolve_access_organization(
        tx,
        input.authenticated.scope,
        input.audience,
        input.request,
    )
    .await?;
    let definitions = repo::roles(tx, input.authenticated.scope).await?;
    let allowed = privileges(&client, input.audience)?;
    let decision = if input.request.admin_access_grant_id.is_some() {
        super::support::authorize(tx, &input, &organization, &allowed).await?
    } else {
        let member = repo::membership(tx, &organization, input.authenticated.user_id)
            .await?
            .ok_or(AuthorityError::Forbidden)?;
        AccessDecision::authorize(AccessInput {
            ceiling: &input.original.ceiling,
            authenticated: input.authenticated,
            request: input.request,
            audience: input.audience,
            current_client_privileges: &allowed,
            organization: &organization,
            member: &member,
            definitions: &definitions,
            parent_expires_at: input.parent_expires_at,
            now: input.now,
        })?
    };
    super::identity::require_current(
        tx,
        input.authenticated,
        input.original.consent.identity_revision,
        input.original.consent.auth_time,
    )
    .await?;
    Ok(SelectedAuthority {
        version: 2,
        epoch: input.original.consent.epoch.clone(),
        issued_at: input.now,
        parent_expires_at: input.parent_expires_at,
        decision,
        domain_revision: input.original.consent.domain_revision,
        client_binding_id: client.id,
        client_binding_revision: client.revision,
    })
}

pub(crate) fn validate_original(
    original: &RootAuthority,
    authenticated: &Binding,
    now: i64,
) -> Result<(), AuthorityError> {
    original.consent.require_current_epoch()?;
    let rebound = original.consent.bind(
        &original.ceiling.binding.root_id,
        original.ceiling.expires_at,
    )?;
    require(
        rebound == *original
            && &original.ceiling.binding == authenticated
            && now >= original.consent.captured_at
            && now < original.ceiling.expires_at,
    )
}

fn privileges(
    client: &operators::mutations::clients::ClientBinding,
    audience: &str,
) -> Result<BTreeSet<String>, AuthorityError> {
    Ok(client
        .targets
        .iter()
        .find(|t| t.audience == audience)
        .ok_or(AuthorityError::Forbidden)?
        .privileges
        .iter()
        .cloned()
        .collect())
}

impl SelectedAuthority {
    pub(crate) fn validate_binding(
        &self,
        original: &RootAuthority,
        authenticated: &Binding,
        now: i64,
    ) -> Result<(), AuthorityError> {
        validate_original(original, authenticated, now)?;
        self.validate_fields(original, authenticated, now)
    }

    /// Validate retained structure at the recorded time, without granting live use.
    pub(super) fn validate_history_binding(
        &self,
        original: &RootAuthority,
        authenticated: &Binding,
        now: i64,
    ) -> Result<(), AuthorityError> {
        original.consent.validate_history(&original.ceiling)?;
        require(
            &original.ceiling.binding == authenticated
                && now >= original.consent.captured_at
                && now < original.ceiling.expires_at,
        )?;
        self.validate_fields(original, authenticated, now)
    }

    fn validate_fields(
        &self,
        original: &RootAuthority,
        authenticated: &Binding,
        now: i64,
    ) -> Result<(), AuthorityError> {
        let consent = &original.consent;
        let ceiling = &original.ceiling;
        let maximum = aegaeon_pure::organization_bounds::selected_expiry(
            ceiling.expires_at,
            self.parent_expires_at,
            self.issued_at,
        )
        .map_err(|_| AuthorityError::Invalid)?;
        require(
            self.issued_at >= consent.captured_at
                && now >= self.issued_at
                && self.decision.expires_at <= maximum,
        )?;
        require(
            self.version == consent.version
                && self.epoch == consent.epoch
                && self.decision.binding == *authenticated
                && self.domain_revision == consent.domain_revision
                && self.client_binding_id == consent.client_binding_id
                && self.client_binding_revision == consent.client_binding_revision
                && self.decision.expires_at > now
                && self.decision.expires_at <= ceiling.expires_at,
        )?;
        self.validate_authority(original)
    }
    fn validate_authority(&self, original: &RootAuthority) -> Result<(), AuthorityError> {
        let ceiling = &original.ceiling;
        let audience = ceiling
            .audiences
            .get(&self.decision.audience)
            .ok_or(AuthorityError::Forbidden)?;
        require(
            !self.decision.privileges.is_empty() && self.decision.privileges.is_subset(audience),
        )?;
        match &self.decision.authority {
            AccessAuthority::Membership {
                incarnation,
                generation,
                ..
            } => {
                let member = ceiling
                    .memberships
                    .get(&self.decision.organization_id)
                    .ok_or(AuthorityError::Forbidden)?;
                require(
                    self.decision.privileges.is_subset(&member.privileges)
                        && *incarnation == member.incarnation
                        && *generation == member.grant_generation
                        && self.decision.organization_generation == member.organization_generation
                        && self
                            .decision
                            .role_versions
                            .iter()
                            .all(|(k, v)| member.role_versions.get(k) == Some(v)),
                )
            }
            AccessAuthority::AdministrativeGrant {
                grant_id,
                grant_revision,
            } => {
                let support = original
                    .consent
                    .support
                    .get(&self.decision.organization_id)
                    .ok_or(AuthorityError::Forbidden)?;
                let evidence = original
                    .consent
                    .original_authentication
                    .as_ref()
                    .ok_or(AuthorityError::Forbidden)?;
                require(
                    !grant_id.is_nil()
                        && *grant_revision > 0
                        && self.decision.expires_at
                            <= evidence
                                .auth_time
                                .checked_add(300)
                                .ok_or(AuthorityError::Exhausted)?
                        && self.decision.privileges.is_subset(&support.privileges)
                        && self.decision.organization_generation == support.organization_generation
                        && self
                            .decision
                            .role_versions
                            .iter()
                            .all(|(k, v)| support.role_versions.get(k) == Some(v)),
                )
            }
        }
    }
}
