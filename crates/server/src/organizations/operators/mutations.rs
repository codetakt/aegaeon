//! Configuration transactions. The caller authenticates the human session and
//! rolls back on every error; these functions never commit on the caller's behalf.
use super::{
    lock_human_scope, lock_operator_authority, validate_capabilities, Capability, MAX_OPERATORS,
};
use crate::organizations::{
    model::{increment, require},
    repository::{ActorKind, AuditActor, RepositoryError},
    AuthorityError, Scope,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

pub mod clients;
pub mod delivery;
pub mod identity_policy;
pub mod lifecycle;
mod receipts;
pub(crate) use receipts::MAX_CONFIGURATION_RECEIPTS;
pub mod role_policy;
pub mod support_policy;
pub mod targets;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorGrant {
    pub id: Uuid,
    pub scope: Scope,
    pub administrator_id: Uuid,
    pub active: bool,
    pub revision: i64,
    pub capabilities: BTreeSet<Capability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultDomain {
    pub scope: Scope,
    pub enabled: bool,
    pub revision: i64,
    pub operator: OperatorGrant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantCommand {
    Create {
        administrator_id: Uuid,
        active: bool,
        capabilities: Vec<Capability>,
    },
    Revoke {
        id: Uuid,
        expected_revision: i64,
    },
    Update {
        id: Uuid,
        expected_revision: i64,
        active: bool,
        capabilities: Vec<Capability>,
    },
}

impl GrantCommand {
    fn operation(&self) -> &'static str {
        match self {
            Self::Create { .. } => "domain.operator.create",
            Self::Update { .. } => "domain.operator.update",
            Self::Revoke { .. } => "domain.operator.revoke",
        }
    }
}

pub async fn bootstrap_default(
    tx: &mut Transaction<'_, Postgres>,
    team: Uuid,
    environment: Uuid,
    actor: &AuditActor,
    key: &str,
) -> Result<DefaultDomain, RepositoryError> {
    receipts::validate_actor(actor, key)?;
    // Lock absence before row creation. Hash collisions serialize unrelated
    // bootstraps; they cannot equate scopes or grant authorization.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('organizations.bootstrap:' || $1::text,0))",
    )
    .bind(environment.to_string())
    .execute(&mut **tx)
    .await?;
    lock_human_scope(tx, team, environment, actor.id, true).await?;
    let existing: Option<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.authorization_domains WHERE environment_id=$1 AND is_default FOR UPDATE")
        .bind(environment).fetch_optional(&mut **tx).await?;
    let scope = Scope {
        environment_id: environment,
        domain_id: existing.unwrap_or_else(Uuid::new_v4),
    };
    let payload = serde_json::json!({"team":team,"environment":environment,"reason":actor.reason});
    let digest = receipts::digest(&payload)?;
    if existing.is_some() {
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
        return receipts::previous(tx, scope, actor, key, "domain.bootstrap", &digest)
            .await?
            .ok_or_else(|| AuthorityError::Conflict.into());
    }
    let audited_actor =
        actor.with_basis(serde_json::json!({"kind":"team_owner_bootstrap","teamId":team}));
    let actor = &audited_actor;
    sqlx::query("INSERT INTO aegaeon.authorization_domains(id,environment_id,name,is_default) VALUES ($1,$2,'default',true)")
        .bind(scope.domain_id).bind(environment).execute(&mut **tx).await?;
    let operator = OperatorGrant {
        id: Uuid::new_v4(),
        scope,
        administrator_id: actor.id,
        active: true,
        revision: 1,
        capabilities: BTreeSet::from([Capability::Configure]),
    };
    insert_grant(tx, &operator).await?;
    let result = DefaultDomain {
        scope,
        enabled: false,
        revision: 1,
        operator,
    };
    receipts::event(
        tx,
        scope,
        actor,
        "domain.bootstrapped",
        receipts::transition(serde_json::to_value(&result)?, None, result.revision)?,
    )
    .await?;
    receipts::save(tx, scope, actor, key, "domain.bootstrap", &digest, &result).await?;
    Ok(result)
}

pub async fn apply_grant_command(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    command: &GrantCommand,
) -> Result<OperatorGrant, RepositoryError> {
    receipts::validate_actor(actor, key)?;
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    let digest = receipts::digest(&serde_json::json!({"command":command,"reason":actor.reason}))?;
    if let Some(previous) =
        receipts::previous(tx, scope, actor, key, command.operation(), &digest).await?
    {
        return Ok(previous);
    }
    let grant = match command {
        GrantCommand::Create {
            administrator_id,
            active,
            capabilities,
        } => {
            let capabilities = validate_capabilities(capabilities)?;
            receipts::capacity(tx, scope, false).await?;
            lock_human_scope(tx, team, scope.environment_id, *administrator_id, false).await?;
            let identities: Vec<Uuid> = sqlx::query_scalar("SELECT administrator_id FROM aegaeon.organization_operator_grants WHERE environment_id=$1 AND domain_id=$2 LIMIT 65")
                .bind(scope.environment_id).bind(scope.domain_id).fetch_all(&mut **tx).await?;
            if identities.contains(administrator_id) {
                return Err(AuthorityError::Conflict.into());
            }
            if identities.len() >= MAX_OPERATORS {
                return Err(AuthorityError::Exhausted.into());
            }
            let grant = OperatorGrant {
                id: Uuid::new_v4(),
                scope,
                administrator_id: *administrator_id,
                active: *active,
                revision: 1,
                capabilities,
            };
            insert_grant(tx, &grant).await?;
            grant
        }
        GrantCommand::Update {
            id,
            expected_revision,
            ..
        }
        | GrantCommand::Revoke {
            id,
            expected_revision,
        } => {
            require(!id.is_nil() && *expected_revision > 0)?;
            let row = sqlx::query("SELECT administrator_id,revision,active,capabilities FROM aegaeon.organization_operator_grants WHERE environment_id=$1 AND domain_id=$2 AND id=$3 FOR UPDATE")
                .bind(scope.environment_id).bind(scope.domain_id).bind(id)
                .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
            let revision: i64 = row.try_get("revision")?;
            if revision != *expected_revision {
                return Err(AuthorityError::PreconditionFailed.into());
            }
            let (active, capabilities) = match command {
                GrantCommand::Update {
                    active,
                    capabilities,
                    ..
                } => (*active, validate_capabilities(capabilities)?),
                GrantCommand::Revoke { .. } => (
                    false,
                    validate_capabilities(&serde_json::from_value::<Vec<Capability>>(
                        row.try_get("capabilities")?,
                    )?)?,
                ),
                GrantCommand::Create { .. } => return Err(AuthorityError::Invalid.into()),
            };
            let administrator_id: Uuid = row.try_get("administrator_id")?;
            receipts::capacity(tx, scope, !active && row.try_get::<bool, _>("active")?).await?;
            // Removed principals may still be revoked; activation requires
            // current membership in this Team, never a stale grant.
            if active {
                lock_human_scope(tx, team, scope.environment_id, administrator_id, false).await?;
            }
            let revision = increment(revision, !active)?;
            sqlx::query("UPDATE aegaeon.organization_operator_grants SET active=$4,revision=$5,capabilities=$6 WHERE environment_id=$1 AND domain_id=$2 AND id=$3")
                .bind(scope.environment_id).bind(scope.domain_id).bind(id).bind(active).bind(revision)
                .bind(serde_json::to_value(&capabilities)?).execute(&mut **tx).await?;
            OperatorGrant {
                id: *id,
                scope,
                administrator_id,
                active,
                revision,
                capabilities,
            }
        }
    };
    audit_grant(tx, scope, actor, command, &grant).await?;
    receipts::save(tx, scope, actor, key, command.operation(), &digest, &grant).await?;
    Ok(grant)
}

async fn audit_grant(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    command: &GrantCommand,
    grant: &OperatorGrant,
) -> Result<(), RepositoryError> {
    let before_revision = match command {
        GrantCommand::Create { .. } => None,
        GrantCommand::Update {
            expected_revision, ..
        }
        | GrantCommand::Revoke {
            expected_revision, ..
        } => Some(*expected_revision),
    };
    receipts::event(
        tx,
        scope,
        actor,
        command.operation(),
        receipts::transition(
            serde_json::to_value(grant)?,
            before_revision,
            grant.revision,
        )?,
    )
    .await?;
    Ok(())
}

async fn insert_grant(
    tx: &mut Transaction<'_, Postgres>,
    grant: &OperatorGrant,
) -> Result<(), RepositoryError> {
    sqlx::query("INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,active,capabilities) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(grant.id).bind(grant.scope.environment_id).bind(grant.scope.domain_id)
        .bind(grant.administrator_id).bind(grant.active).bind(serde_json::to_value(&grant.capabilities)?)
        .execute(&mut **tx).await?;
    Ok(())
}
