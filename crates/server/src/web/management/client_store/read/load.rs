use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

use crate::management::types::Client;

use super::super::super::management_internal_error;
use super::super::mapper::client_from_row_result;

pub(in crate::web::management) const LOAD_VISIBLE_CLIENT_ROW_SQL: &str = r#"
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
  to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(c.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.clients c
JOIN aegaeon.environments e
  ON e.id = c.environment_id
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE c.id = $1
  AND c.environment_id = $2
  AND c.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND t.status <> 'DELETED'
  AND t.team_id = $3
        "#;

pub(in crate::web::management) async fn load_visible_client(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    request_id: &str,
) -> Result<Option<Client>, Response> {
    let Some(row) =
        load_visible_client_row(pool, team_id, environment_id, client_id, request_id).await?
    else {
        return Ok(None);
    };
    client_from_row_result(&row, request_id).map(Some)
}

async fn load_visible_client_row(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    client_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(LOAD_VISIBLE_CLIENT_ROW_SQL)
        .bind(client_id)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
