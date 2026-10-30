//! Explicit domain transitions; the revision is a required token-use fence.
use super::*;

pub async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    expected_revision: i64,
    enabled: bool,
) -> Result<targets::DomainConfiguration, RepositoryError> {
    receipts::validate_actor(actor, key)?;
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    require(expected_revision > 0)?;
    let operation = if enabled {
        "domain.enable"
    } else {
        "domain.disable"
    };
    let digest = receipts::digest(
        &serde_json::json!({"revision":expected_revision,"enabled":enabled,"reason":actor.reason}),
    )?;
    if let Some(previous) = receipts::previous(tx, scope, actor, key, operation, &digest).await? {
        return Ok(previous);
    }
    let mut result = targets::read_locked(tx, scope).await?;
    if result.revision != expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    if result.enabled == enabled {
        return Err(AuthorityError::Conflict.into());
    }
    receipts::capacity(tx, scope, !enabled).await?;
    if enabled {
        if result.targets.is_empty() {
            return Err(AuthorityError::Forbidden.into());
        }
        clients::require_activation_ready(tx, scope, team, actor.id).await?;
    }
    result.revision = increment(result.revision, !enabled)?;
    result.enabled = enabled;
    sqlx::query("UPDATE aegaeon.authorization_domains SET enabled=$3,revision=$4 WHERE environment_id=$1 AND id=$2")
        .bind(scope.environment_id).bind(scope.domain_id).bind(enabled).bind(result.revision).execute(&mut **tx).await?;
    receipts::event(
        tx,
        scope,
        actor,
        operation,
        receipts::transition(
            serde_json::json!({"enabled":enabled,"revision":result.revision}),
            Some(expected_revision),
            result.revision,
        )?,
    )
    .await?;
    receipts::save(tx, scope, actor, key, operation, &digest, &result).await?;
    Ok(result)
}
