use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

use super::super::super::management_internal_error;

pub(in crate::web::management) const LIST_CLIENT_ROWS_SQL: &str = r#"
SELECT
  c.id,
  c.environment_id,
  c.oauth_profile_id,
  c.client_identifier,
  c.name,
  c.client_type::text AS client_type,
  c.redirect_uris,
  c.allowed_grant_types,
  c.allowed_scopes,
  c.token_endpoint_authentication_method,
  to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  c.id::text AS id_cursor,
  to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(c.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.clients c
JOIN aegaeon.environments e
  ON e.id = c.environment_id
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE c.environment_id = $1
  AND c.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND t.status <> 'DELETED'
  AND t.team_id = $2
  AND ($3::timestamptz IS NULL OR (c.created_at, c.id) > ($3::timestamptz, $4::uuid))
ORDER BY c.created_at ASC, c.id ASC
LIMIT $5
        "#;

pub(in crate::web::management) async fn list_client_rows(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    cursor_created_at: Option<&str>,
    cursor_id: Option<&str>,
    limit: i64,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(LIST_CLIENT_ROWS_SQL)
        .bind(environment_id)
        .bind(team_id)
        .bind(cursor_created_at)
        .bind(cursor_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
