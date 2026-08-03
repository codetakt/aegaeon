use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

use super::super::super::management_internal_error;
use crate::web::management::pagination::KeysetPagination;

pub(in crate::web::management) const LIST_OAUTH_PROFILE_ROWS_SQL: &str = r#"
SELECT
  op.id,
  op.environment_id,
  op.configuration_version_id,
  op.name,
  op.description,
  op.profile_type::text AS profile_type,
  op.is_default,
  op.require_pkce,
  op.require_state_parameter,
  op.require_iss_parameter,
  op.sender_constrained::text AS sender_constrained,
  op.enforce_refresh_sender_binding,
  op.allowed_grant_types,
  op.token_endpoint_auth_methods_allowed,
  to_char(op.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS expires_at,
  op.status::text AS status,
  to_char(op.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at_cursor,
  op.id::text AS id_cursor,
  to_char(op.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at,
  to_char(op.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS updated_at
FROM aegaeon.oauth_profiles op
JOIN aegaeon.environments e ON e.id = op.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE op.environment_id = $1
  AND op.configuration_version_id = $2
  AND t.team_id = $3
  AND op.status <> 'RETIRED'
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND ($4::timestamptz IS NULL OR (op.created_at, op.id) > ($4::timestamptz, $5::uuid))
ORDER BY op.created_at ASC, op.id ASC
LIMIT $6
        "#;

pub(in crate::web::management) async fn list_oauth_profile_rows(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    pagination: &KeysetPagination,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(LIST_OAUTH_PROFILE_ROWS_SQL)
        .bind(environment_id)
        .bind(configuration_version_id)
        .bind(team_id)
        .bind(pagination.cursor_value(0))
        .bind(pagination.cursor_value(1))
        .bind(pagination.limit.saturating_add(1))
        .fetch_all(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
