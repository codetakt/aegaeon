//! Exact target registration. It supplies no client or business authorization.
use super::*;

pub mod recipients;

pub const MAX_TARGETS: usize = 32;
pub const MAX_TARGET_BYTES: usize = 48 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Target {
    pub audience: String,
    pub management: bool,
    #[serde(default)]
    pub introspection_clients: Vec<recipients::Recipient>,
}

impl Target {
    pub(in crate::organizations) fn validate(&self) -> Result<(), AuthorityError> {
        recipients::validate(&self.introspection_clients)?;
        require(
            !self.audience.trim().is_empty()
                && self.audience.len() <= 2048
                && !self.audience.chars().any(char::is_control),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DomainConfiguration {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub environment_id: Uuid,
    pub enabled: bool,
    pub revision: i64,
    pub targets: Vec<Target>,
}

#[derive(Debug, Serialize)]
pub struct RegisterTarget {
    pub expected_revision: i64,
    pub target: Target,
}

/// The caller authenticates a human session and owns rollback/commit.
pub async fn read_configuration(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
) -> Result<DomainConfiguration, RepositoryError> {
    lock_operator_authority(tx, scope, team, principal, Capability::Configure).await?;
    read_locked(tx, scope).await
}

pub(super) async fn read_locked(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<DomainConfiguration, RepositoryError> {
    let row = sqlx::query("SELECT enabled,revision FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_one(&mut **tx).await?;
    let rows = sqlx::query("SELECT audience,management,introspection_clients FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 ORDER BY audience COLLATE \"C\" LIMIT 33")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_all(&mut **tx).await?;
    let mut targets = Vec::with_capacity(rows.len());
    for row in rows {
        let target = Target {
            audience: row.try_get("audience")?,
            management: row.try_get("management")?,
            introspection_clients: serde_json::from_value(row.try_get("introspection_clients")?)?,
        };
        target.validate()?;
        targets.push(target);
    }
    capacity(&targets)?;
    let revision = row.try_get("revision")?;
    require(revision > 0)?;
    Ok(DomainConfiguration {
        id: scope.domain_id,
        environment_id: scope.environment_id,
        enabled: row.try_get("enabled")?,
        revision,
        targets,
    })
}

pub(super) fn capacity(targets: &[Target]) -> Result<(), RepositoryError> {
    if targets.len() > MAX_TARGETS || serde_json::to_vec(targets)?.len() > MAX_TARGET_BYTES {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(())
}

pub async fn register(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    command: &RegisterTarget,
) -> Result<DomainConfiguration, RepositoryError> {
    receipts::validate_actor(actor, key)?;
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    require(command.expected_revision > 0)?;
    command.target.validate()?;
    require(command.target.introspection_clients.is_empty())?;
    let digest = receipts::digest(&serde_json::json!({"command":command,"reason":actor.reason}))?;
    const OPERATION: &str = "domain.target.register";
    if let Some(previous) = receipts::previous(tx, scope, actor, key, OPERATION, &digest).await? {
        return Ok(previous);
    }
    let mut result = read_locked(tx, scope).await?;
    if result.revision != command.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    receipts::capacity(tx, scope, false).await?;
    result.targets.push(command.target.clone());
    result.targets.sort_by(|a, b| a.audience.cmp(&b.audience));
    capacity(&result.targets)?;
    result.revision = increment(result.revision, false)?;
    // Environment-wide uniqueness resolves races with other domain locks. It
    // never transfers an existing audience or reveals the other domain's ID.
    let changed = sqlx::query("INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management) VALUES ($1,$2,$3,$4) ON CONFLICT(environment_id,audience) DO NOTHING")
        .bind(scope.environment_id).bind(scope.domain_id).bind(&command.target.audience)
        .bind(command.target.management).execute(&mut **tx).await?;
    if changed.rows_affected() != 1 {
        return Err(AuthorityError::Conflict.into());
    }
    sqlx::query(
        "UPDATE aegaeon.authorization_domains SET revision=$3 WHERE environment_id=$1 AND id=$2",
    )
    .bind(scope.environment_id)
    .bind(scope.domain_id)
    .bind(result.revision)
    .execute(&mut **tx)
    .await?;
    receipts::event(
        tx,
        scope,
        actor,
        OPERATION,
        receipts::transition(
            serde_json::to_value(&command.target)?,
            Some(command.expected_revision),
            result.revision,
        )?,
    )
    .await?;
    receipts::save(tx, scope, actor, key, OPERATION, &digest, &result).await?;
    Ok(result)
}
