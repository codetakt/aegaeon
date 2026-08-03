use axum::{http::StatusCode, response::Response};
use sqlx::{PgPool, Row};

use super::super::http_errors::{error_response, management_internal_error};
use super::super::AppState;

pub(in crate::web::management) async fn validate_expires_at(
    pool: &PgPool,
    expires_at: Option<&str>,
    request_id: &str,
) -> Result<(), Response> {
    let Some(value) = expires_at else {
        return Ok(());
    };

    let row = sqlx::query("SELECT $1::timestamptz > now() AS is_future")
        .bind(value)
        .fetch_optional(pool)
        .await;

    let Ok(row) = row else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "expiresAt must be a valid RFC3339 timestamp",
            None,
            Some(request_id),
        ));
    };

    let Some(row) = row else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "expiresAt must be a valid RFC3339 timestamp",
            None,
            Some(request_id),
        ));
    };

    let is_future: bool = row
        .try_get("is_future")
        .map_err(|_| management_internal_error(request_id, "Failed to validate expiresAt"))?;
    if !is_future {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "expiresAt must be in the future",
            None,
            Some(request_id),
        ));
    }

    Ok(())
}

pub(in crate::web::management) fn management_db_pool<'a>(
    state: &'a AppState,
    request_id: &str,
) -> Result<&'a PgPool, Response> {
    if state.db_pool.is_closed() {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Database pool is closed",
            None,
            Some(request_id),
        ));
    }
    Ok(&state.db_pool)
}
