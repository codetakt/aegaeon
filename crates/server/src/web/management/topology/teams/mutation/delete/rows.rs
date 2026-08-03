use super::super::super::super::super::management_internal_error;
use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) async fn lock_team_lifecycle_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query(
        r"
SELECT t.id
FROM aegaeon.teams t
WHERE t.id = $1
  AND t.status <> 'DELETED'
FOR UPDATE OF t
        ",
    )
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_some())
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

pub(super) async fn delete_team_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
UPDATE aegaeon.teams
SET status = 'DELETED', deleted_at = now(), updated_at = now()
WHERE id = $1
  AND status <> 'DELETED'
        ",
    )
    .bind(team_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

pub(super) async fn team_has_active_tenants(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query(
        r"
SELECT EXISTS (
  SELECT 1
  FROM aegaeon.tenants
  WHERE team_id = $1
    AND status = 'ACTIVE'
)
        ",
    )
    .bind(team_id)
    .fetch_one(&mut **tx)
    .await
    .and_then(|row| row.try_get("exists"))
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
