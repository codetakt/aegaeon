use super::super::super::{error_response, management_internal_error};
use axum::{http::StatusCode, response::Response};
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

pub(in crate::web::management) const FETCH_CONFIGURATION_VERSION_ROW_SQL: &str = r#"
SELECT
  cv.id,
  cv.environment_id,
  cv.version_number,
  cv.schema_version,
  cv.configuration_hash,
  cv.status::text AS status,
  cv.comment,
  to_char(cv.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  cv.configuration_document
FROM aegaeon.configuration_versions cv
JOIN aegaeon.environments e
  ON e.id = cv.environment_id
JOIN aegaeon.tenants t
  ON t.id = e.tenant_id
WHERE cv.id = $1
  AND cv.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
        "#;

pub(super) async fn fetch_configuration_version_rows(
    pool: &PgPool,
    environment_id: Uuid,
    cursor_version_number: Option<&str>,
    cursor_id: Option<&str>,
    limit_plus_one: i64,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(
        r#"
SELECT
  id,
  environment_id,
  version_number,
	  version_number::text AS version_number_cursor,
	  id::text AS id_cursor,
	  schema_version,
	  configuration_hash,
	  status::text AS status,
	  comment,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
FROM aegaeon.configuration_versions
WHERE environment_id = $1
  AND ($2::integer IS NULL OR (version_number, id) < ($2::integer, $3::uuid))
ORDER BY version_number DESC, id DESC
LIMIT $4
        "#,
    )
    .bind(environment_id)
    .bind(cursor_version_number)
    .bind(cursor_id)
    .bind(limit_plus_one)
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

pub(super) async fn fetch_configuration_version_row(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<Option<PgRow>, Response> {
    sqlx::query(FETCH_CONFIGURATION_VERSION_ROW_SQL)
        .bind(configuration_version_id)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
