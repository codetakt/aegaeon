use std::time::Duration;

use sqlx::PgPool;
use thiserror::Error;

const MIN_STALE_ACTIVE_COMMAND_SECS: u64 = 120;
const MAX_RECONCILED_COMMANDS_PER_PASS: i64 = 100;
const RECONCILER_ACTOR_ID: &str = "management_runtime_command_reconciler";
const STALE_RECONCILIATION_SQL: &str = r"
WITH stale AS (
  SELECT
    command.id,
    command.status::text AS previous_status
  FROM aegaeon.management_user_runtime_commands AS command
  WHERE command.status IN (
      'requested'::aegaeon.management_runtime_command_status,
      'executing'::aegaeon.management_runtime_command_status
    )
    AND command.updated_at < now() - ($1::bigint * interval '1 second')
  ORDER BY command.updated_at ASC
  FOR UPDATE OF command SKIP LOCKED
  LIMIT $2
),
updated AS (
  UPDATE aegaeon.management_user_runtime_commands AS command
  SET status = 'failed_unconfirmed'::aegaeon.management_runtime_command_status,
      phase = COALESCE(command.phase, 'reconciliation'),
      result = jsonb_build_object(
        'reason', 'staleRuntimeCommand',
        'previousStatus', stale.previous_status,
        'staleAfterSeconds', $1,
        'reconciledBy', $3
      ),
      execution_started_at = COALESCE(command.execution_started_at, now()),
      updated_at = now(),
      completed_at = now()
  FROM stale
  WHERE command.id = stale.id
  RETURNING
    command.id,
    command.team_id,
    command.tenant_id,
    command.environment_id,
    command.end_user_id,
    command.actor_administrator_id,
    command.request_id,
    command.command_type,
    command.phase,
    command.payload,
    command.result
),
audit AS (
  INSERT INTO aegaeon.audit_events (
    team_id,
    tenant_id,
    environment_id,
    event_type,
    category,
    outcome,
    severity,
    occurred_at,
    actor_type,
    actor_id,
    target_type,
    target_id,
    request_id,
    data
  )
  SELECT
    team_id,
    tenant_id,
    environment_id,
    'management.user.runtimeCommand.reconciledStale.v1',
    'CONTROL_PLANE',
    'FAILURE',
    'ERROR',
    now(),
    'SYSTEM',
    $3,
    'END_USER',
    end_user_id::text,
    request_id,
    jsonb_build_object(
      'commandId', id::text,
      'commandType', command_type,
      'phase', phase,
      'payloadPresent', payload IS NOT NULL,
      'result', result,
      'actorAdministratorId', actor_administrator_id::text
    )
  FROM updated
  RETURNING 1
)
SELECT count(*)::bigint FROM audit
";

#[derive(Debug, Error)]
pub enum RuntimeCommandReconciliationError {
    #[error("runtime command stale threshold cannot be represented")]
    StaleThresholdOverflow,

    #[error("runtime command stale threshold must be positive")]
    EmptyStaleThreshold,

    #[error("runtime command reconciliation query failed: {0}")]
    Database(#[from] sqlx::Error),
}

#[must_use]
pub fn runtime_command_stale_after(cleanup_interval_secs: u64) -> Duration {
    Duration::from_secs(
        cleanup_interval_secs
            .saturating_mul(2)
            .max(MIN_STALE_ACTIVE_COMMAND_SECS),
    )
}

pub async fn reconcile_stale_management_user_runtime_commands(
    pool: &PgPool,
    stale_after: Duration,
) -> Result<u64, RuntimeCommandReconciliationError> {
    let stale_after_secs = stale_after.as_secs();
    if stale_after_secs == 0 {
        return Err(RuntimeCommandReconciliationError::EmptyStaleThreshold);
    }
    let stale_after_secs = i64::try_from(stale_after_secs)
        .map_err(|_| RuntimeCommandReconciliationError::StaleThresholdOverflow)?;

    sqlx::query_scalar::<_, i64>(STALE_RECONCILIATION_SQL)
        .bind(stale_after_secs)
        .bind(MAX_RECONCILED_COMMANDS_PER_PASS)
        .bind(RECONCILER_ACTOR_ID)
        .fetch_one(pool)
        .await?
        .try_into()
        .map_err(|_| RuntimeCommandReconciliationError::StaleThresholdOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_after_is_derived_from_cleanup_interval_with_floor() {
        assert_eq!(runtime_command_stale_after(1), Duration::from_secs(120));
        assert_eq!(runtime_command_stale_after(60), Duration::from_secs(120));
        assert_eq!(runtime_command_stale_after(75), Duration::from_secs(150));
    }

    #[test]
    fn stale_reconciliation_query_is_locking_and_audited() {
        assert!(STALE_RECONCILIATION_SQL.contains("FOR UPDATE OF command SKIP LOCKED"));
        assert!(STALE_RECONCILIATION_SQL.contains("'failed_unconfirmed'"));
        assert!(
            STALE_RECONCILIATION_SQL.contains("management.user.runtimeCommand.reconciledStale.v1")
        );
        assert!(STALE_RECONCILIATION_SQL.contains("status IN"));
        assert!(STALE_RECONCILIATION_SQL.contains("'requested'"));
        assert!(STALE_RECONCILIATION_SQL.contains("'executing'"));
        assert!(STALE_RECONCILIATION_SQL.contains("'payloadPresent', payload IS NOT NULL"));
        assert!(!STALE_RECONCILIATION_SQL.contains("'payload', payload"));
    }
}
