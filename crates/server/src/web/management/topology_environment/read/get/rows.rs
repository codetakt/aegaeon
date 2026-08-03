use crate::web::management::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(super) async fn get_environment_row(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(
        r#"
SELECT
  e.id,
  e.tenant_id,
  e.name,
  e.slug,
  e.issuer_host,
  e.issuer_url,
  e.active_configuration_version_id,
  to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(e.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.environments e
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE e.id = $1
  AND t.team_id = $2
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
        "#,
    )
    .bind(environment_id)
    .bind(team_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
