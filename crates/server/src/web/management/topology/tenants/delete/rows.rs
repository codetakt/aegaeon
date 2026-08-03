use crate::web::management::management_internal_error;
use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) async fn lock_tenant_lifecycle_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    tenant_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query(
        r"
SELECT t.id
FROM aegaeon.tenants t
JOIN aegaeon.teams team
  ON team.id = t.team_id
WHERE t.id = $1
  AND t.team_id = $2
  AND t.status <> 'DELETED'
  AND team.status <> 'DELETED'
FOR UPDATE OF t
        ",
    )
    .bind(tenant_id)
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_some())
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

pub(super) async fn delete_tenant_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    tenant_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
UPDATE aegaeon.tenants
SET status = 'DELETED', deleted_at = now(), updated_at = now()
WHERE id = $1
  AND team_id = $2
  AND status <> 'DELETED'
        ",
    )
    .bind(tenant_id)
    .bind(team_id)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

pub(super) async fn tenant_has_active_environments(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    tenant_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query(
        r"
SELECT EXISTS (
  SELECT 1
  FROM aegaeon.environments e
  JOIN aegaeon.tenants t
    ON t.id = e.tenant_id
  WHERE e.tenant_id = $1
    AND t.team_id = $2
    AND e.status = 'ACTIVE'
)
        ",
    )
    .bind(tenant_id)
    .bind(team_id)
    .fetch_one(&mut **tx)
    .await
    .and_then(|row| row.try_get("exists"))
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
