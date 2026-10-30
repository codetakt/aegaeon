//! Retained invitation authority, distinct from the expired issuing access token.
use super::super::{consent::RootAuthority, request_work::Admission, selected::SelectedAuthority};
use super::*;
use crate::authcode::{store::RetainedRoot, types::BearerTokenMeta, TokenStore};

mod mutations;
pub(crate) use mutations::{inspect, issue, revoke, Request};

pub(crate) struct Runtime<'a> {
    pub store: &'a TokenStore,
    pub admission: &'a Admission,
    pub issuer: &'a str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retained {
    version: u32,
    retained_until: i64,
    pub(super) original: RootAuthority,
    pub(super) selected: SelectedAuthority,
    liveness: RetainedRoot,
}

impl Retained {
    /// Structural historical validation at the original issue time. This does
    /// not consult Redis and cannot establish present root or inviter liveness.
    pub(super) fn validate_history(
        &self,
        actor: &AuditActor,
        scope: Scope,
        invitation: &Invitation,
    ) -> Result<(), AuthorityError> {
        let binding = &self.original.ceiling.binding;
        self.selected
            .validate_binding(&self.original, binding, self.selected.issued_at)?;
        require(
            self.version == 1
                && binding.scope == scope
                && self.selected.issued_at <= invitation.issued_at
                && invitation.expires_at <= self.retained_until
                && self.retained_until <= self.original.ceiling.expires_at
                && self.liveness.root.id == binding.root_id
                && self.liveness.client == binding.client_id
                && self.liveness.subject == binding.subject
                && self
                    .liveness
                    .refresh_grant
                    .as_ref()
                    .is_none_or(|reference| reference.supported())
                && crate::util::unix_epoch_secs(self.liveness.root.expires_at)
                    .ok()
                    .and_then(|n| i64::try_from(n).ok())
                    == Some(self.original.ceiling.expires_at)
                && actor.id == binding.user_id
                && actor.client_id == binding.client_id
                && actor.client_registration_id == Some(binding.client_registration_id)
                && self.selected.decision.organization_id == invitation.organization_id,
        )
    }

    pub(super) async fn capture(
        meta: &BearerTokenMeta,
        scope: Scope,
        now: i64,
        runtime: &Runtime<'_>,
    ) -> Result<Self, RepositoryError> {
        let grant = meta
            .exchange_grant
            .as_ref()
            .ok_or(AuthorityError::Forbidden)?;
        let original = grant
            .organization
            .as_ref()
            .ok_or(AuthorityError::Forbidden)?;
        let selected = meta
            .selected_organization
            .as_ref()
            .ok_or(AuthorityError::Forbidden)?;
        let binding =
            selected.token_binding(meta, scope.environment_id, &original.consent.issuer, now)?;
        require(binding.scope == scope && binding == original.ceiling.binding)?;
        selected.validate_binding(original, &binding, now)?;
        let root = grant.root().ok_or(AuthorityError::Forbidden)?.clone();
        require(
            root.id == binding.root_id
                && crate::util::unix_epoch_secs(root.expires_at)
                    .ok()
                    .and_then(|v| i64::try_from(v).ok())
                    == Some(original.ceiling.expires_at),
        )?;
        let liveness = RetainedRoot {
            root,
            refresh_grant: meta.refresh_grant.clone(),
            client: meta.client_id.clone(),
            subject: meta.user_id.clone(),
        };
        let retained_until = current_deadline(runtime, &liveness).await?;
        Ok(Self {
            version: 1,
            retained_until,
            original: original.clone(),
            selected: selected.clone(),
            liveness,
        })
    }

    pub(super) fn deadline(&self) -> i64 {
        self.retained_until
    }

    pub(super) async fn check(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        stored: &Stored,
        scope: Scope,
        now: i64,
        runtime: Option<&Runtime<'_>>,
    ) -> Result<Organization, RepositoryError> {
        let runtime = runtime.ok_or(AuthorityError::Forbidden)?;
        let binding = &self.original.ceiling.binding;
        require(
            self.version == 1
                && binding.scope == scope
                && binding.issuer == runtime.issuer
                && now >= self.selected.issued_at
                && now < self.deadline()
                && self.deadline() <= self.original.ceiling.expires_at
                && self.liveness.root.id == binding.root_id
                && self.liveness.client == binding.client_id
                && self.liveness.subject == binding.subject
                && matches!(stored.authority.actor.kind, ActorKind::Member)
                && stored.authority.actor.id == binding.user_id
                && stored.authority.actor.client_id == binding.client_id
                && stored.authority.actor.client_registration_id
                    == Some(binding.client_registration_id)
                && self.selected.decision.organization_id == stored.invitation.organization_id,
        )?;
        if current_deadline(runtime, &self.liveness).await? < self.deadline() {
            return Err(AuthorityError::Forbidden.into());
        }
        // Check the issued snapshot at its fixed birth time, against current
        // primary rows. The invitation's root lifetime is checked above; this
        // does not make an expired selected token usable at any resource API.
        require(
            selected::is_current(
                tx,
                &self.selected,
                &self.original,
                binding,
                self.selected.issued_at,
            )
            .await?,
        )?;
        let org = repo::lock_organization(tx, scope, stored.invitation.organization_id).await?;
        require(
            org.state == OrganizationState::Active
                && org.grant_generation == stored.authority.organization_generation
                && stored.invitation.state != State::Revoked
                && cap::is_live(
                    cap::Purpose::Invitation,
                    stored.invitation.issued_at,
                    stored.invitation.expires_at,
                    now,
                ),
        )?;
        let member = repo::membership(tx, &org, binding.user_id)
            .await?
            .ok_or(AuthorityError::Forbidden)?;
        let roles = repo::roles(tx, scope).await?;
        let assign: BTreeSet<_> = stored.authority.role_versions.keys().cloned().collect();
        require(
            !assign.is_empty()
                && assign.len() <= MAX_ROLES
                && stored.authority.role_versions.iter().all(|(key, version)| {
                    roles.get(key).is_some_and(|role| role.version == *version)
                }),
        )?;
        super::super::delegation::authorize_membership_change(
            &super::super::delegation::DelegationInput {
                access: &self.selected.decision,
                authenticated: binding,
                management_audience: &self.selected.decision.audience,
                current_client_privileges: &self.selected.decision.privileges,
                organization: &org,
                actor_membership: &member,
                definitions: &roles,
                assign_roles: &assign,
                now: self.selected.issued_at,
            },
        )?;
        let management: Option<bool> = sqlx::query_scalar("SELECT management FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
            .bind(scope.environment_id).bind(scope.domain_id).bind(&self.selected.decision.audience).fetch_optional(&mut **tx).await?;
        require(management == Some(true))?;
        Ok(org)
    }
}

async fn current_deadline(
    runtime: &Runtime<'_>,
    retained: &RetainedRoot,
) -> Result<i64, RepositoryError> {
    let store = runtime.store.clone();
    let retained = retained.clone();
    let lease = runtime.admission.clone();
    let deadline = tokio::task::spawn_blocking(move || {
        let _lease = lease;
        store.retained_root_deadline(&retained)
    })
    .await
    .map_err(|_| RepositoryError::Unavailable)?
    .map_err(|_| RepositoryError::Unavailable)?
    .ok_or(AuthorityError::Forbidden)?;
    crate::util::unix_epoch_secs(deadline)
        .ok()
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| AuthorityError::Invalid.into())
}
