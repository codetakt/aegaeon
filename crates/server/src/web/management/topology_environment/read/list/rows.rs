use crate::web::management::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(super) async fn list_environment_rows(
    pool: &PgPool,
    team_id: Uuid,
    tenant_id: Uuid,
    cursor_created_at: Option<&str>,
    cursor_id: Option<&str>,
    limit_plus_one: i64,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(
        r#"
SELECT
  e.id,
  e.name,
  e.slug,
  e.issuer_host,
  e.issuer_url,
  e.active_configuration_version_id,
  to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  e.id::text AS id_cursor,
  to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(e.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.environments e
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE t.id = $1
  AND t.team_id = $2
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND ($3::timestamptz IS NULL OR (e.created_at, e.id) > ($3::timestamptz, $4::uuid))
ORDER BY e.created_at ASC, e.id ASC
LIMIT $5
        "#,
    )
    .bind(tenant_id)
    .bind(team_id)
    .bind(cursor_created_at)
    .bind(cursor_id)
    .bind(limit_plus_one)
    .fetch_all(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
