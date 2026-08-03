use crate::web::management::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(super) async fn list_tenant_rows(
    pool: &PgPool,
    team_id: Uuid,
    cursor_created_at: Option<&str>,
    cursor_id: Option<&str>,
    limit_plus_one: i64,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(
        r#"
SELECT
  id,
  team_id,
  slug,
  name,
  region,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  id::text AS id_cursor,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.tenants
WHERE team_id = $1
  AND status <> 'DELETED'
  AND ($2::timestamptz IS NULL OR (created_at, id) > ($2::timestamptz, $3::uuid))
ORDER BY created_at ASC, id ASC
LIMIT $4
        "#,
    )
    .bind(team_id)
    .bind(cursor_created_at)
    .bind(cursor_id)
    .bind(limit_plus_one)
    .fetch_all(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
