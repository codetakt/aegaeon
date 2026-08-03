use super::super::super::error_response;
use axum::{http::StatusCode, response::Response};
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(in crate::web::management) const LIST_CLIENT_SECRET_ROWS_SQL: &str = r#"
SELECT
  cs.id,
  cs.client_id,
  cs.status::text AS status,
  cs.active_slot,
  to_char(cs.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(cs.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
FROM aegaeon.client_secrets cs
JOIN aegaeon.clients c ON c.id = cs.client_id
JOIN aegaeon.environments e ON e.id = c.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE cs.client_id = $1
  AND e.id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
ORDER BY cs.created_at ASC
        "#;

pub(in crate::web::management::client_secrets) async fn list_client_secret_rows(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(LIST_CLIENT_SECRET_ROWS_SQL)
        .bind(client_id)
        .bind(environment_id)
        .bind(team_id)
        .fetch_all(pool)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Database query failed",
                None,
                Some(request_id),
            )
        })
}
