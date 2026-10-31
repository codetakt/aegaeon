//! Transaction-scoped persistence. Callers authenticate operator or delegated
//! authority before entering these methods; no method accepts profile claims.
//! The web boundary owns commit, so its permission recheck and this mutation
//! share one transaction. There is deliberately no implicit auto-commit path.

use super::model::{require, roles_for};
use super::{
    AuthorityError, Membership, MembershipState, Organization, OrganizationState, RoleDefinition,
    Scope,
};
use serde::{Deserialize, Serialize};
pub(crate) mod recovery;

use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("organization authority supplier unavailable")]
    Unavailable,
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error("organization storage unavailable")]
    Storage(#[from] sqlx::Error),
    #[error("invalid persisted organization authority")]
    Decode(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Operator,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditActor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) basis: Option<serde_json::Value>,
    pub id: Uuid,
    pub kind: ActorKind,
    pub client_id: String,
    pub client_registration_id: Option<Uuid>,
    pub request_id: String,
    pub reason: String,
}

impl AuditActor {
    pub(crate) fn with_basis(&self, basis: serde_json::Value) -> Self {
        Self {
            basis: Some(basis),
            ..self.clone()
        }
    }

    pub(crate) fn with_operator(
        &self,
        authority: &super::operators::OperatorAuthority,
        capability: super::operators::Capability,
    ) -> Self {
        self.with_basis(serde_json::json!({"kind":"domain_operator","grantId":authority.grant(),"revision":authority.revision(),"capability":capability}))
    }

    pub(super) fn validate(&self) -> Result<(), AuthorityError> {
        require(!self.id.is_nil())?;
        if let Some(basis) = &self.basis {
            require(
                basis.is_object()
                    && serde_json::to_vec(basis)
                        .map_err(|_| AuthorityError::Invalid)?
                        .len()
                        <= 32 * 1024,
            )?;
        }
        require(match self.kind {
            ActorKind::Operator => self.client_registration_id.is_none(),
            ActorKind::Member => self.client_registration_id.is_some_and(|id| !id.is_nil()),
        })?;
        for (value, limit) in [
            (&self.client_id, 255),
            (&self.request_id, 255),
            (&self.reason, 1024),
        ] {
            require(
                !value.trim().is_empty()
                    && value.len() <= limit
                    && !value.chars().any(char::is_control),
            )?;
        }
        Ok(())
    }
}

/// Lock domain before organization before membership/user. Domain locks also
/// serialize policy edits, so last-admin checks use stable role definitions.
pub async fn lock_domain(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<(), RepositoryError> {
    scope.validate()?;
    let enabled: Option<bool> = sqlx::query_scalar("SELECT enabled FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 AND import_operation_id IS NULL FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_optional(&mut **tx).await?;
    if enabled != Some(true) {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(())
}

pub async fn lock_organization(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
) -> Result<Organization, RepositoryError> {
    lock_domain(tx, scope).await?;
    let row = sqlx::query("SELECT external_id,state,revision,grant_generation FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2 AND id=$3 FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id)
        .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let value = Organization {
        scope,
        id,
        external_id: row.try_get("external_id")?,
        state: serde_json::from_value(serde_json::json!(row.try_get::<String, _>("state")?))?,
        revision: row.try_get("revision")?,
        grant_generation: row.try_get("grant_generation")?,
    };
    value.validate()?;
    Ok(value)
}

/// Resolve an opaque selector only inside the authenticated scope and the
/// registered target's domain. This is lookup, not a membership authorization:
/// the caller must still validate identity, ceiling, client policy and root and
/// call `AccessDecision::authorize` in this same transaction before disclosure.
/// Domain -> target -> organization locking keeps target assignment and enabled
/// state stable with respect to authority mutations until the transaction ends.
pub async fn resolve_access_organization(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    audience: &str,
    request: &super::AccessRequest,
) -> Result<Organization, RepositoryError> {
    request.validate()?;
    require(
        !audience.is_empty() && audience.len() <= 2048 && !audience.chars().any(char::is_control),
    )?;
    lock_domain(tx, scope).await?;
    let domain: Option<Uuid> = sqlx::query_scalar("SELECT domain_id FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND audience=$2 FOR SHARE")
        .bind(scope.environment_id).bind(audience).fetch_optional(&mut **tx).await?;
    if domain != Some(scope.domain_id) {
        return Err(AuthorityError::Forbidden.into());
    }
    let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2 AND external_id=$3 COLLATE \"C\"")
        .bind(scope.environment_id).bind(scope.domain_id).bind(&request.identifier)
        .fetch_optional(&mut **tx).await?;
    let organization = lock_organization(tx, scope, id.ok_or(AuthorityError::Forbidden)?).await?;
    if organization.state != OrganizationState::Active {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(organization)
}

pub async fn roles(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<BTreeMap<String, RoleDefinition>, RepositoryError> {
    let rows = sqlx::query("SELECT role_key,version,privileges,manages_members,assignable_roles FROM aegaeon.organization_role_definitions WHERE environment_id=$1 AND domain_id=$2 ORDER BY role_key LIMIT 65")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_all(&mut **tx).await?;
    require(rows.len() <= super::MAX_ROLES)?;
    let mut values = BTreeMap::new();
    for row in rows {
        let role = RoleDefinition {
            scope,
            key: row.try_get("role_key")?,
            version: row.try_get("version")?,
            privileges: serde_json::from_value(row.try_get("privileges")?)?,
            manages_members: row.try_get("manages_members")?,
            assignable_roles: serde_json::from_value(row.try_get("assignable_roles")?)?,
        };
        role.validate()?;
        values.insert(role.key.clone(), role);
    }
    Ok(values)
}

pub async fn membership(
    tx: &mut Transaction<'_, Postgres>,
    organization: &Organization,
    user: Uuid,
) -> Result<Option<Membership>, RepositoryError> {
    let row = sqlx::query("SELECT incarnation,state,revision,grant_generation,roles FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2 AND organization_id=$3 AND end_user_id=$4")
        .bind(organization.scope.environment_id).bind(organization.scope.domain_id)
        .bind(organization.id).bind(user).fetch_optional(&mut **tx).await?;
    row.map(|row| {
        let value = Membership {
            scope: organization.scope,
            organization_id: organization.id,
            user_id: user,
            incarnation: row.try_get("incarnation")?,
            state: serde_json::from_value(serde_json::json!(row.try_get::<String, _>("state")?))?,
            revision: row.try_get("revision")?,
            grant_generation: row.try_get("grant_generation")?,
            roles: serde_json::from_value(row.try_get("roles")?)?,
        };
        value.validate()?;
        Ok(value)
    })
    .transpose()
}

pub async fn require_active_identity(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    user: Uuid,
    subject: Option<&str>,
) -> Result<(), RepositoryError> {
    let active: Option<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND id=$2 AND status='ACTIVE' AND ($3::text IS NULL OR subject=$3) FOR SHARE")
        .bind(scope.environment_id).bind(user).bind(subject).fetch_optional(&mut **tx).await?;
    if active.is_none() {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(())
}

pub async fn create_organization(
    tx: &mut Transaction<'_, Postgres>,
    organization: &Organization,
    actor: &AuditActor,
) -> Result<(), RepositoryError> {
    organization.validate()?;
    require(
        organization.state == OrganizationState::Provisioning
            && organization.revision == 1
            && organization.grant_generation == 1,
    )?;
    lock_domain(tx, organization.scope).await?;
    super::commands::capacity::creation(tx, organization.scope, &organization.external_id).await?;
    sqlx::query("INSERT INTO aegaeon.application_organizations (id,environment_id,domain_id,external_id,state) VALUES ($1,$2,$3,$4,'provisioning')")
        .bind(organization.id).bind(organization.scope.environment_id).bind(organization.scope.domain_id)
        .bind(&organization.external_id).execute(&mut **tx).await?;
    event(
        tx,
        organization,
        actor,
        "organization.created",
        serde_json::json!({"revision":1,"before":null,"after":{"state":organization.state,"revision":organization.revision,"generation":organization.grant_generation}}),
    )
    .await
}

pub async fn transition_organization(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
    expected_revision: i64,
    state: OrganizationState,
    actor: &AuditActor,
) -> Result<Organization, RepositoryError> {
    let mut organization = lock_organization(tx, scope, id).await?;
    if state == OrganizationState::Active
        && administrator_count(tx, &organization, None).await? == 0
    {
        return Err(AuthorityError::Forbidden.into());
    }
    let before = organization.clone();
    organization.transition(expected_revision, state)?;
    sqlx::query("UPDATE aegaeon.application_organizations SET state=$4,revision=$5,grant_generation=$6 WHERE environment_id=$1 AND domain_id=$2 AND id=$3")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id)
        .bind(serde_json::to_value(state)?.as_str().ok_or(AuthorityError::Invalid)?)
        .bind(organization.revision).bind(organization.grant_generation).execute(&mut **tx).await?;
    event(
        tx,
        &organization,
        actor,
        "organization.state_changed",
        serde_json::json!({"state":state,"revision":organization.revision,"before":{"state":before.state,"revision":before.revision,"generation":before.grant_generation},"after":{"state":organization.state,"revision":organization.revision,"generation":organization.grant_generation}}),
    )
    .await?;
    Ok(organization)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipUpdate {
    pub user_id: Uuid,
    pub expected_revision: i64,
    pub state: MembershipState,
    pub roles: BTreeSet<String>,
}

pub async fn update_membership(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    organization_id: Uuid,
    update: MembershipUpdate,
    actor: &AuditActor,
) -> Result<Membership, RepositoryError> {
    let organization = lock_organization(tx, scope, organization_id).await?;
    if matches!(
        organization.state,
        OrganizationState::Suspended | OrganizationState::Deleted
    ) {
        return Err(AuthorityError::Forbidden.into());
    }
    let existing = membership(tx, &organization, update.user_id).await?;
    let before = existing.as_ref().map(membership_version);
    let mut member = match existing {
        Some(mut member) => {
            member.update(update.expected_revision, update.state, update.roles)?;
            member
        }
        None => {
            require(
                update.expected_revision == 0
                    && !matches!(
                        update.state,
                        MembershipState::Removed | MembershipState::Suspended
                    ),
            )?;
            Membership {
                scope,
                organization_id,
                user_id: update.user_id,
                incarnation: Uuid::new_v4(),
                state: update.state,
                revision: 1,
                grant_generation: 1,
                roles: update.roles,
            }
        }
    };
    member.validate()?;
    let definitions = roles(tx, scope).await?;
    let member_roles = roles_for(&member, &definitions)?;
    let is_admin = member.state == MembershipState::Active
        && member_roles.iter().any(|role| role.manages_members);
    if organization.state == OrganizationState::Active
        && !is_admin
        && administrator_count(tx, &organization, Some(member.user_id)).await? == 0
    {
        return Err(AuthorityError::Forbidden.into());
    }
    // Activation requires an active identity in the same Environment. A revoked
    // identity may still have its membership removed without being reactivated.
    if member.state == MembershipState::Active {
        require_active_identity(tx, scope, member.user_id, None).await?;
    }
    if member.state == MembershipState::Removed {
        member.roles.clear();
    }
    save_membership(tx, &member).await?;
    event(tx, &organization, actor, "organization.membership_changed", serde_json::json!({"user_id":member.user_id,"state":member.state,"roles":member.roles,"revision":member.revision,"generation":member.grant_generation,"incarnation":member.incarnation,"before":before,"after":membership_version(&member)})).await?;
    Ok(member)
}

fn membership_version(member: &Membership) -> serde_json::Value {
    serde_json::json!({"state":member.state,"revision":member.revision,"generation":member.grant_generation,"incarnation":member.incarnation})
}

async fn save_membership(
    tx: &mut Transaction<'_, Postgres>,
    member: &Membership,
) -> Result<(), RepositoryError> {
    sqlx::query("INSERT INTO aegaeon.organization_memberships (environment_id,domain_id,organization_id,end_user_id,incarnation,state,revision,grant_generation,roles) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (environment_id,domain_id,organization_id,end_user_id) DO UPDATE SET state=EXCLUDED.state,revision=EXCLUDED.revision,grant_generation=EXCLUDED.grant_generation,roles=EXCLUDED.roles")
        .bind(member.scope.environment_id).bind(member.scope.domain_id).bind(member.organization_id).bind(member.user_id)
        .bind(member.incarnation).bind(serde_json::to_value(member.state)?.as_str().ok_or(AuthorityError::Invalid)?)
        .bind(member.revision).bind(member.grant_generation).bind(serde_json::to_value(&member.roles)?)
        .execute(&mut **tx).await?;
    Ok(())
}

async fn administrator_count(
    tx: &mut Transaction<'_, Postgres>,
    organization: &Organization,
    excluding: Option<Uuid>,
) -> Result<i64, RepositoryError> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM aegaeon.organization_memberships m JOIN aegaeon.end_users u ON u.id=m.end_user_id AND u.environment_id=m.environment_id AND u.status='ACTIVE' WHERE m.environment_id=$1 AND m.domain_id=$2 AND m.organization_id=$3 AND m.state='active' AND ($4::uuid IS NULL OR m.end_user_id<>$4) AND EXISTS (SELECT 1 FROM aegaeon.organization_role_definitions r WHERE r.environment_id=m.environment_id AND r.domain_id=m.domain_id AND r.manages_members AND m.roles ? r.role_key)")
        .bind(organization.scope.environment_id).bind(organization.scope.domain_id).bind(organization.id).bind(excluding)
        .fetch_one(&mut **tx).await?)
}

pub(super) async fn event(
    tx: &mut Transaction<'_, Postgres>,
    organization: &Organization,
    actor: &AuditActor,
    kind: &str,
    mut data: serde_json::Value,
) -> Result<(), RepositoryError> {
    actor.validate()?;
    if let Some(basis) = &actor.basis {
        data.as_object_mut()
            .ok_or(AuthorityError::Invalid)?
            .insert("authorityBasis".into(), basis.clone());
    }
    crate::organizations::audit::retention::validate_data(&data)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.organization_authority_events (id,environment_id,domain_id,organization_id,actor_id,actor_kind,client_id,request_id,reason,event_type,data,client_registration_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(id).bind(organization.scope.environment_id).bind(organization.scope.domain_id).bind(organization.id)
        .bind(actor.id).bind(serde_json::to_value(&actor.kind)?.as_str().ok_or(AuthorityError::Invalid)?)
        .bind(&actor.client_id).bind(&actor.request_id).bind(&actor.reason).bind(kind).bind(data).bind(actor.client_registration_id).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO aegaeon.organization_authority_outbox (event_id) VALUES ($1)")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
