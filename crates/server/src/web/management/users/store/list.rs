use super::super::super::management_internal_error;
use crate::web::management::pagination::KeysetPagination;
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(in crate::web::management) const LIST_USER_ROWS_SQL: &str = r#"
SELECT
  u.id,
  u.environment_id,
  u.subject,
  u.email,
  u.status::text AS status,
  to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  u.id::text AS id_cursor,
  to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.end_users u
JOIN aegaeon.environments e ON e.id = u.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.environment_id = $1
  AND ($2 OR u.status <> 'DELETED')
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND ($4::timestamptz IS NULL OR (u.created_at, u.id) > ($4::timestamptz, $5::uuid))
ORDER BY u.created_at ASC, u.id ASC
LIMIT $6
        "#;

pub(in crate::web::management::users) async fn list_user_rows(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    include_deleted: bool,
    pagination: &KeysetPagination,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(LIST_USER_ROWS_SQL)
        .bind(environment_id)
        .bind(include_deleted)
        .bind(team_id)
        .bind(pagination.cursor_value(0))
        .bind(pagination.cursor_value(1))
        .bind(pagination.limit.saturating_add(1))
        .fetch_all(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
