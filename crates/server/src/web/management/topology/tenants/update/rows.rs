use crate::web::management::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn update_tenant_row(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    tenant_id: Uuid,
    name: &str,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
UPDATE aegaeon.tenants
SET name = $1, updated_at = now()
WHERE id = $2
  AND team_id = $3
  AND status <> 'DELETED'
RETURNING
  id,
  slug,
  name,
  region,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(name)
    .bind(tenant_id)
    .bind(team_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
