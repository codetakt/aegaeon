use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::super::super::{error_response, management_internal_error, required_row_value};

pub(in crate::web::management) async fn switch_active_configuration_version(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    previous_configuration_version_id: Uuid,
    next_configuration_version_id: Uuid,
    request_id: &str,
) -> Result<String, Response> {
    if previous_configuration_version_id != next_configuration_version_id {
        sqlx::query(
            r"
UPDATE aegaeon.configuration_versions
SET status = 'ARCHIVED', archived_at = now()
WHERE id = $1
  AND environment_id = $2
  AND status = 'ACTIVE'
            ",
        )
        .bind(previous_configuration_version_id)
        .bind(environment_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| {
            management_internal_error(request_id, "Failed to archive previous configuration")
        })?;
    }

    let result = sqlx::query(
        r"
UPDATE aegaeon.configuration_versions
SET status = 'ACTIVE', activated_at = now()
WHERE id = $1 AND environment_id = $2
  AND status <> 'ARCHIVED'
        ",
    )
    .bind(next_configuration_version_id)
    .bind(environment_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to activate configuration"))?;
    if result.rows_affected() != 1 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Configuration version is archived or unavailable",
            None,
            Some(request_id),
        ));
    }

    let row = sqlx::query(
        r#"
UPDATE aegaeon.environments
SET active_configuration_version_id = $1, updated_at = now()
WHERE id = $2
RETURNING to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(next_configuration_version_id)
    .bind(environment_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to update environment"))?;

    required_row_value(
        &row,
        "updated_at",
        request_id,
        "Failed to read updated environment",
    )
}
