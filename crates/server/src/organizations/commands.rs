//! Receipt-backed mutations. The enclosing transaction must roll back on any
//! error. Authorization is rechecked before receipt lookup, including replays.
use super::repository::{self, ActorKind, AuditActor, MembershipUpdate, RepositoryError};
use super::{AuthorityError, Membership, Organization, OrganizationState, Scope};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(crate) mod capacity;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Create {
        external_id: String,
    },
    PrepareAdministratorRecovery {
        organization_id: Uuid,
        expected_revision: i64,
    },
    SetState {
        organization_id: Uuid,
        expected_revision: i64,
        state: OrganizationState,
    },
    SetMember {
        organization_id: Uuid,
        update: MembershipUpdate,
    },
    SetExistingMember {
        organization_id: Uuid,
        expected_incarnation: Uuid,
        update: MembershipUpdate,
    },
}

impl Command {
    fn operation(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::SetState { .. } => "set_state",
            Self::PrepareAdministratorRecovery { .. } => "prepare_administrator_recovery",
            Self::SetMember { .. } => "set_member",
            Self::SetExistingMember { .. } => "set_existing_member",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CommandResult {
    Organization(Organization),
    Membership(Membership),
}

/// The management boundary authenticates the actor; persisted provisioning
/// authority is rechecked here before receipts, including response-loss retries.
pub async fn apply_operator_command(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    command: &Command,
) -> Result<CommandResult, RepositoryError> {
    if !matches!(actor.kind, ActorKind::Operator)
        || !matches!(
            command,
            Command::Create { .. }
                | Command::SetState { .. }
                | Command::PrepareAdministratorRecovery { .. }
        )
    {
        return Err(AuthorityError::Forbidden.into());
    }
    if matches!(command, Command::PrepareAdministratorRecovery { .. }) {
        super::operators::lock_human_scope(tx, team, scope.environment_id, actor.id, true).await?;
    }
    let authority = super::operators::lock_operator_authority(
        tx,
        scope,
        team,
        actor.id,
        super::operators::Capability::Provision,
    )
    .await?;
    let actor = actor.with_operator(&authority, super::operators::Capability::Provision);
    apply_authorized(tx, scope, &actor, key, command).await
}

/// Called by the delegated boundary only after authenticating DPoP/root and
/// verifying this issued access decision against the registered management target.
pub async fn apply_member_command(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    key: &str,
    command: &Command,
    authority: &super::delegation::DelegationInput<'_>,
) -> Result<CommandResult, RepositoryError> {
    let (Command::SetMember {
        organization_id,
        update,
    }
    | Command::SetExistingMember {
        organization_id,
        update,
        ..
    }) = command
    else {
        return Err(AuthorityError::Forbidden.into());
    };
    if !matches!(actor.kind, ActorKind::Member)
        || actor.id != authority.authenticated.user_id
        || actor.client_id != authority.authenticated.client_id
        || actor.client_registration_id != Some(authority.authenticated.client_registration_id)
        || scope != authority.authenticated.scope
        || *organization_id != authority.access.organization_id
        || &update.roles != authority.assign_roles
    {
        return Err(AuthorityError::Forbidden.into());
    }
    let organization = repository::lock_organization(tx, scope, *organization_id).await?;
    repository::require_active_identity(
        tx,
        scope,
        actor.id,
        Some(&authority.authenticated.subject),
    )
    .await?;
    let member = repository::membership(tx, &organization, actor.id)
        .await?
        .ok_or(AuthorityError::Forbidden)?;
    let roles = repository::roles(tx, scope).await?;
    let input = super::delegation::DelegationInput {
        organization: &organization,
        actor_membership: &member,
        definitions: &roles,
        ..*authority
    };
    super::delegation::authorize_membership_change(&input)?;
    // Replacing a member's roles requires authority over both removed and added
    // roles, so a limited administrator cannot strip a stronger administrator.
    if let Some(target) = repository::membership(tx, &organization, update.user_id).await? {
        let old = super::delegation::DelegationInput {
            assign_roles: &target.roles,
            ..input
        };
        super::delegation::authorize_membership_change(&old)?;
    }
    let actor = actor.with_basis(serde_json::json!({"kind":"delegated_membership","rootId":authority.authenticated.root_id,"membershipIncarnation":member.incarnation,"membershipRevision":member.revision,"membershipGeneration":member.grant_generation,"organizationGeneration":organization.grant_generation,"roleVersions":authority.access.role_versions}));
    apply_authorized(tx, scope, &actor, key, command).await
}

async fn apply_authorized(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    key: &str,
    command: &Command,
) -> Result<CommandResult, RepositoryError> {
    actor.validate()?;
    super::model::require(
        !key.is_empty() && key.len() <= 128 && !key.chars().any(char::is_control),
    )?;
    let actor_kind = serde_json::to_value(&actor.kind)?;
    let actor_kind = actor_kind.as_str().ok_or(AuthorityError::Invalid)?;
    // serde_json objects use ordered keys; command sets also serialize in order.
    // The request ID is transport metadata and deliberately not part of replay identity.
    let payload =
        serde_json::to_vec(&serde_json::json!({"command":command,"reason":actor.reason}))?;
    let digest = aegaeon_crypto::hash::sha256_digest(&payload);
    let registration = actor.client_registration_id.unwrap_or(Uuid::nil());
    let previous = sqlx::query("SELECT request_digest,result FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND actor_id=$3 AND actor_kind=$4 AND client_id=$5 AND operation=$6 AND idempotency_key=$7 AND client_registration_id=$8")
        .bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(actor_kind)
        .bind(&actor.client_id).bind(command.operation()).bind(key).bind(registration).fetch_optional(&mut **tx).await?;
    if let Some(row) = previous {
        if row.try_get::<Vec<u8>, _>("request_digest")? != digest.as_ref() {
            return Err(AuthorityError::Conflict.into());
        }
        return Ok(serde_json::from_value(row.try_get("result")?)?);
    }
    if matches!(actor.kind, ActorKind::Operator) {
        capacity::operator(tx, scope, command).await?;
    } else {
        capacity::member(tx, scope, command).await?;
    }
    let result = execute(tx, scope, actor, command).await?;
    sqlx::query("INSERT INTO aegaeon.organization_authority_receipts (environment_id,domain_id,actor_id,actor_kind,client_id,operation,idempotency_key,request_digest,result,client_registration_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(actor_kind)
        .bind(&actor.client_id).bind(command.operation()).bind(key).bind(digest.as_ref())
        .bind(serde_json::to_value(&result)?).bind(registration).execute(&mut **tx).await?;
    Ok(result)
}

async fn execute(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    command: &Command,
) -> Result<CommandResult, RepositoryError> {
    match command {
        Command::PrepareAdministratorRecovery {
            organization_id,
            expected_revision,
        } => Ok(CommandResult::Organization(
            repository::recovery::prepare(tx, scope, *organization_id, *expected_revision, actor)
                .await?,
        )),
        Command::Create { external_id } => {
            let organization = Organization {
                scope,
                id: Uuid::new_v4(),
                external_id: external_id.clone(),
                state: OrganizationState::Provisioning,
                revision: 1,
                grant_generation: 1,
            };
            repository::create_organization(tx, &organization, actor).await?;
            Ok(CommandResult::Organization(organization))
        }
        Command::SetState {
            organization_id,
            expected_revision,
            state,
        } => Ok(CommandResult::Organization(
            repository::transition_organization(
                tx,
                scope,
                *organization_id,
                *expected_revision,
                *state,
                actor,
            )
            .await?,
        )),
        Command::SetMember {
            organization_id,
            update,
        } => Ok(CommandResult::Membership(
            repository::update_membership(tx, scope, *organization_id, update.clone(), actor)
                .await?,
        )),
        Command::SetExistingMember {
            organization_id,
            expected_incarnation,
            update,
        } => {
            let organization = repository::lock_organization(tx, scope, *organization_id).await?;
            let member = repository::membership(tx, &organization, update.user_id)
                .await?
                .ok_or(AuthorityError::Forbidden)?;
            if member.incarnation != *expected_incarnation
                || member.revision != update.expected_revision
            {
                return Err(AuthorityError::PreconditionFailed.into());
            }
            if !matches!(
                member.state,
                super::MembershipState::Active | super::MembershipState::Suspended
            ) || !matches!(
                update.state,
                super::MembershipState::Active
                    | super::MembershipState::Suspended
                    | super::MembershipState::Removed
            ) {
                return Err(AuthorityError::Forbidden.into());
            }
            Ok(CommandResult::Membership(
                repository::update_membership(tx, scope, *organization_id, update.clone(), actor)
                    .await?,
            ))
        }
    }
}
