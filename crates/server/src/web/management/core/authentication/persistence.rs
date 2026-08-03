use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;
use uuid::Uuid;

use super::super::super::{error_response, management_internal_error, required_row_value};

pub(super) struct ManagementLoginRecord {
    pub(super) administrator_id: Uuid,
    pub(super) password_hash: String,
    pub(super) status: String,
}

pub(super) async fn load_management_login_record(
    pool: &PgPool,
    email: &str,
    request_id: &str,
) -> Result<Option<ManagementLoginRecord>, Response> {
    let Ok(row) = sqlx::query(
        r"
SELECT id, password_hash, status::text
FROM aegaeon.administrators
WHERE email = $1
        ",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    else {
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Database query failed",
            None,
            Some(request_id),
        ));
    };

    let Some(row) = row else {
        return Ok(None);
    };

    let message = "Invalid administrator record";
    Ok(Some(ManagementLoginRecord {
        administrator_id: required_row_value(&row, "id", request_id, message)?,
        password_hash: required_row_value(&row, "password_hash", request_id, message)?,
        status: required_row_value(&row, "status", request_id, message)?,
    }))
}

pub(super) async fn update_management_login_state(
    pool: &PgPool,
    administrator_id: Uuid,
    verified_password_hash: &str,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query(
        r"
UPDATE aegaeon.administrators
SET last_login_at = now(), updated_at = now()
WHERE id = $1
  AND password_hash = $2
  AND status = 'ACTIVE'
RETURNING id
        ",
    )
    .bind(administrator_id)
    .bind(verified_password_hash)
    .fetch_optional(pool)
    .await
    .map(|row| row.is_some())
    .map_err(|_| management_internal_error(request_id, "Failed to update login state"))
}
