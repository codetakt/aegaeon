use axum::{http::StatusCode, response::Response};

use super::super::error_response;

pub(in crate::web::management) fn invalid_email_response(request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Email must be a valid address",
        None,
        Some(request_id),
    )
}

pub(in crate::web::management) fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some("23505")
    )
}

pub(in crate::web::management) fn user_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "User not found",
        None,
        Some(request_id),
    )
}

pub(in crate::web::management) fn user_profile_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "User profile not found",
        None,
        Some(request_id),
    )
}
