use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

use crate::management::types::OAuthProfile;

use super::super::super::management_internal_error;
use super::super::mapper::oauth_profile_from_row_result;

pub(in crate::web::management) async fn load_oauth_profile(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    oauth_profile_id: Uuid,
    request_id: &str,
) -> Result<Option<OAuthProfile>, Response> {
    let Some(row) =
        load_oauth_profile_row(pool, team_id, environment_id, oauth_profile_id, request_id).await?
    else {
        return Ok(None);
    };
    oauth_profile_from_row_result(&row, request_id).map(Some)
}

pub(in crate::web::management) const LOAD_OAUTH_PROFILE_ROW_SQL: &str = r#"
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
  to_char(op.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at,
  to_char(op.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS updated_at
FROM aegaeon.oauth_profiles op
JOIN aegaeon.environments e ON e.id = op.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE op.id = $1
  AND op.environment_id = $2
  AND t.team_id = $3
  AND op.status <> 'RETIRED'
  AND e.status <> 'DELETED'
  AND t.status <> 'DELETED'
        "#;

async fn load_oauth_profile_row(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    oauth_profile_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(LOAD_OAUTH_PROFILE_ROW_SQL)
        .bind(oauth_profile_id)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
