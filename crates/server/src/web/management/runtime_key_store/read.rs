use super::super::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(in crate::web::management) async fn list_runtime_key_rows(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(
        r#"
SELECT
  rk.id,
  rk.environment_id,
  rk.usage::text AS usage,
  rk.kid,
  rk.algorithm,
  rk.provider::text AS provider,
  rk.status::text AS status,
	  rk.public_jwk,
	  rk.provider_configuration,
	  to_char(rk.retiring_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS retiring_expires_at,
	  to_char(rk.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
	FROM aegaeon.runtime_keys rk
JOIN aegaeon.environments e ON e.id = rk.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE rk.environment_id = $1
  AND t.team_id = $2
  AND e.status <> 'DELETED'
  AND t.status <> 'DELETED'
ORDER BY rk.usage ASC, rk.status ASC, rk.created_at ASC, rk.id ASC
        "#,
    )
    .bind(environment_id)
    .bind(team_id)
    .fetch_all(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
