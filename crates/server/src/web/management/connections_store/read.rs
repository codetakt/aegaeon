use axum::{http::StatusCode, response::Response};
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

use crate::management::types::Connection;
use crate::web::management::pagination::KeysetPagination;

use super::super::{error_response, management_internal_error};
use super::mapper::connection_from_row_result;

pub(in crate::web::management) fn connection_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Connection not found",
        None,
        Some(request_id),
    )
}

pub(in crate::web::management) const LIST_CONNECTION_ROWS_SQL: &str = r#"
SELECT
  c.id,
  c.environment_id,
  c.configuration_version_id,
  c.oauth_profile_id,
  c.connection_identifier,
  c.name,
  c.connection_type::text AS connection_type,
  c.issuer_url,
  c.client_id,
  c.client_auth_method,
  c.status::text AS status,
  to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  c.id::text AS id_cursor,
  to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(c.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.connections c
JOIN aegaeon.environments e ON e.id = c.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE c.environment_id = $1
  AND c.configuration_version_id = $2
  AND t.team_id = $3
  AND c.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND t.status <> 'DELETED'
  AND ($4::timestamptz IS NULL OR (c.created_at, c.id) > ($4::timestamptz, $5::uuid))
ORDER BY c.created_at ASC, c.id ASC
LIMIT $6
        "#;

pub(in crate::web::management) async fn list_connection_rows(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    pagination: &KeysetPagination,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(LIST_CONNECTION_ROWS_SQL)
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

pub(in crate::web::management) async fn load_connection(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    connection_id: Uuid,
    request_id: &str,
) -> Result<Option<Connection>, Response> {
    let Some(row) =
        load_connection_row(pool, team_id, environment_id, connection_id, request_id).await?
    else {
        return Ok(None);
    };
    connection_from_row_result(&row, request_id).map(Some)
}

pub(in crate::web::management) const LOAD_CONNECTION_ROW_SQL: &str = r#"
SELECT
  c.id,
  c.environment_id,
  c.configuration_version_id,
  c.oauth_profile_id,
  c.connection_identifier,
  c.name,
  c.connection_type::text AS connection_type,
  c.issuer_url,
  c.client_id,
  c.client_auth_method,
  c.status::text AS status,
  to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(c.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.connections c
JOIN aegaeon.environments e ON e.id = c.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE c.id = $1
  AND c.environment_id = $2
  AND t.team_id = $3
  AND c.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND t.status <> 'DELETED'
        "#;

async fn load_connection_row(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    connection_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(LOAD_CONNECTION_ROW_SQL)
        .bind(connection_id)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
