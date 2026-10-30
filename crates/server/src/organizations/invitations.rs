//! First-administrator invitation transactions. Network authentication and
//! committed delivery belong to the consuming boundary, not a supplied UUID.
use super::{invitation_capabilities as cap, model::require, repository as repo, *};
use repo::{ActorKind, AuditActor, RepositoryError};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

mod acceptance;
mod audit;
pub(crate) mod delegated;
mod delivery;
pub(crate) mod enrollment;
mod history_validation;
mod issue;
pub(in crate::organizations) use history_validation::validate_row as validate_history_row;
pub(crate) mod recipient;
pub(crate) mod transport;
pub(crate) mod worker;
pub(crate) use acceptance::{accept_current, request_challenge_current};
pub use acceptance::{accept_first_admin, request_challenge, Acceptance};
pub use delivery::{claim_challenge_delivery, claim_invitation_delivery, Delivery};
pub use issue::{issue_first_admin, revoke, FirstAdminRequest, Issuance, Revocation};

pub const MAX_INVITATIONS: i64 = 10_000;
pub const MAX_CHALLENGES: i64 = 5;
pub const MAX_DELIVERIES: i64 = 5;
pub const DELIVERY_INTERVAL_SECONDS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationInvitationState))]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Revoked,
    Accepted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Invitation {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub organization_id: Uuid,
    pub revision: i64,
    pub state: State,
    pub issued_at: i64,
    pub expires_at: i64,
}

pub async fn read(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
    id: Uuid,
) -> Result<Invitation, RepositoryError> {
    operators::lock_operator_authority(
        tx,
        scope,
        team,
        principal,
        operators::Capability::Reconcile,
    )
    .await?;
    Ok(load_authorized(tx, scope, id).await?.invitation)
}

/// Facts established by the authenticated recipient boundary on every call.
/// Deserializing this value is never authentication. It is retained only for
/// exact challenge/replay matching and does not select an identity by email.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub binding: Binding,
    pub identity_revision: i64,
    pub auth_time: i64,
    pub expires_at: i64,
}

impl Recipient {
    async fn check(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        scope: Scope,
        now: i64,
    ) -> Result<(), RepositoryError> {
        self.binding.validate()?;
        require(self.binding.scope == scope && now >= 0 && now < self.expires_at)?;
        require(serde_json::to_vec(self)?.len() <= 4096)?;
        super::identity::require_current(tx, &self.binding, self.identity_revision, self.auth_time)
            .await
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegated: Option<delegated::Retained>,
    team: Uuid,
    actor: AuditActor,
    grant: Uuid,
    grant_revision: i64,
    organization_generation: i64,
    role_versions: BTreeMap<String, i64>,
}

struct Stored {
    invitation: Invitation,
    authority: Authority,
    recipient: String,
    delivery_revision: i64,
    delivered_at: Option<i64>,
    hash: Option<Vec<u8>>,
    accepted_challenge: Option<Uuid>,
    result: Option<Membership>,
}

/// This supported mailbox profile preserves case in the local part.
pub fn recipient_address(value: &str) -> Result<String, AuthorityError> {
    require(value.is_ascii() && value.len() <= 254)?;
    let (local, domain) = value.split_once('@').ok_or(AuthorityError::Invalid)?;
    require(!local.is_empty() && local.len() <= 64 && !domain.is_empty() && domain.len() <= 253)?;
    require(local.split('.').all(|part| {
        !part.is_empty()
            && part
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&c))
    }))?;
    require(domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }))?;
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

async fn load(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
) -> Result<Stored, RepositoryError> {
    // Read immutable authority only to establish the global human -> domain ->
    // organization -> invitation lock order. No disclosure or decision yet.
    let authority: Option<serde_json::Value> = sqlx::query_scalar("SELECT authority FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2 AND id=$3")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id).fetch_optional(&mut **tx).await?;
    let authority: Authority = serde_json::from_value(authority.ok_or(AuthorityError::Forbidden)?)?;
    if authority.delegated.is_some() {
        require(matches!(authority.actor.kind, ActorKind::Member))?;
        selected::lock_primary_scope(tx, scope).await?;
    } else {
        operators::lock_operator_authority(
            tx,
            scope,
            authority.team,
            authority.actor.id,
            operators::Capability::Provision,
        )
        .await?;
    }
    load_authorized(tx, scope, id).await
}

async fn load_authorized(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
) -> Result<Stored, RepositoryError> {
    let organization: Option<Uuid> = sqlx::query_scalar("SELECT organization_id FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2 AND id=$3")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id).fetch_optional(&mut **tx).await?;
    repo::lock_organization(tx, scope, organization.ok_or(AuthorityError::Forbidden)?).await?;
    let row = sqlx::query("SELECT * FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2 AND id=$3 FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id)
        .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    Ok(Stored {
        invitation: Invitation {
            id,
            organization_id: row.try_get("organization_id")?,
            revision: row.try_get("revision")?,
            state: serde_json::from_value(serde_json::json!(row.try_get::<String, _>("state")?))?,
            issued_at: row.try_get("issued_at")?,
            expires_at: row.try_get("expires_at")?,
        },
        authority: serde_json::from_value(row.try_get("authority")?)?,
        recipient: row.try_get("recipient")?,
        delivery_revision: row.try_get("delivery_revision")?,
        delivered_at: row.try_get("delivered_at")?,
        hash: row.try_get("capability_hash")?,
        accepted_challenge: row.try_get("accepted_challenge_id")?,
        result: row
            .try_get::<Option<serde_json::Value>, _>("result")?
            .map(serde_json::from_value)
            .transpose()?,
    })
}

async fn current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    stored: &Stored,
    now: i64,
) -> Result<Organization, RepositoryError> {
    current_with_runtime(tx, scope, stored, now, None).await
}

async fn current_with_runtime(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    stored: &Stored,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Organization, RepositoryError> {
    let a = &stored.authority;
    if let Some(delegated) = &a.delegated {
        return delegated.check(tx, stored, scope, now, runtime).await;
    }
    require(matches!(a.actor.kind, ActorKind::Operator))?;
    let authority = operators::lock_operator_authority(
        tx,
        scope,
        a.team,
        a.actor.id,
        operators::Capability::Provision,
    )
    .await?;
    require(authority.grant() == a.grant && authority.revision() == a.grant_revision)?;
    let org = repo::lock_organization(tx, scope, stored.invitation.organization_id).await?;
    let (state, generation) = if stored.invitation.state == State::Accepted {
        (
            OrganizationState::Active,
            a.organization_generation
                .checked_add(1)
                .ok_or(AuthorityError::Exhausted)?,
        )
    } else {
        (OrganizationState::Provisioning, a.organization_generation)
    };
    if org.state != state
        || org.grant_generation != generation
        || stored.invitation.state == State::Revoked
        || !cap::is_live(
            cap::Purpose::Invitation,
            stored.invitation.issued_at,
            stored.invitation.expires_at,
            now,
        )
    {
        return Err(AuthorityError::Forbidden.into());
    }
    let definitions = repo::roles(tx, scope).await?;
    require(!a.role_versions.is_empty() && a.role_versions.len() <= MAX_ROLES)?;
    for (key, version) in &a.role_versions {
        require(
            definitions
                .get(key)
                .is_some_and(|role| role.version == *version),
        )?;
    }
    require(a.role_versions.keys().any(|key| {
        definitions
            .get(key)
            .is_some_and(|role| role.manages_members)
    }))?;
    Ok(org)
}

fn matches_secret(
    scope: Scope,
    id: Uuid,
    revision: i64,
    purpose: cap::Purpose,
    hash: Option<&[u8]>,
    presented: &str,
) -> bool {
    let Some(expected) = hash.and_then(|v| <&[u8; 32]>::try_from(v).ok()) else {
        return false;
    };
    cap::matches(
        cap::Binding {
            scope,
            object_id: id,
            delivery_revision: revision,
            purpose,
        },
        expected,
        presented,
    )
}

fn request_key(key: &str) -> Result<(), AuthorityError> {
    require(!key.is_empty() && key.len() <= 128 && !key.chars().any(char::is_control))
}

async fn event(
    tx: &mut Transaction<'_, Postgres>,
    org: &Organization,
    actor: &AuditActor,
    id: Uuid,
    revision: i64,
    kind: &str,
) -> Result<(), RepositoryError> {
    repo::event(
        tx,
        org,
        actor,
        kind,
        serde_json::json!({"invitation_id":id,"revision":revision,"before":if revision == 1 { serde_json::Value::Null } else { serde_json::json!({"revision":revision - 1}) },"after":{"revision":revision}}),
    )
    .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn organization_invitation_mailbox_preserves_local_part_and_rejects_unsupported_forms() {
        assert_eq!(
            super::recipient_address("User+tag@EXAMPLE.Test").unwrap(),
            "User+tag@example.test"
        );
        assert_ne!(
            super::recipient_address("User@example.test").unwrap(),
            super::recipient_address("user@example.test").unwrap()
        );
        for invalid in [
            "a@@example.test",
            "a..b@example.test",
            "a@-example.test",
            " a@example.test",
            "a@ex ample.test",
            "\"a\"@example.test",
            "user@例.test",
            "user@example.test\r\nBcc:b@c",
            ".a@example.test",
            "a.@example.test",
            "a@example..test",
        ] {
            assert!(super::recipient_address(invalid).is_err(), "{invalid:?}");
        }
    }
}

pub(crate) async fn recheck(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
    now: i64,
    runtime: &delegated::Runtime<'_>,
) -> Result<(), RepositoryError> {
    let stored = load(tx, scope, id).await?;
    current_with_runtime(tx, scope, &stored, now, Some(runtime)).await?;
    Ok(())
}
