use crate::web::management::http_errors::management_database_error as database_error;
use crate::web::management::request_support::owned::reads;
use axum::response::Response;
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
    reads::all(
        pool,
        sqlx::query(LIST_CLIENT_SECRET_ROWS_SQL)
            .bind(client_id)
            .bind(environment_id)
            .bind(team_id),
        request_id,
    )
    .await?
    .map_err(|error| database_error(request_id, &error, "Database query failed"))
}
