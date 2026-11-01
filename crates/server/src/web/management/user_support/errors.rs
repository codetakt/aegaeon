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

/// Stable ownership conflicts do not disclose the historical owner or subject.
pub(in crate::web::management) fn subject_ownership_error(
    error: &sqlx::Error,
    request_id: &str,
) -> Option<Response> {
    let sqlx::Error::Database(error) = error else {
        return None;
    };
    let (status, code, message) = match (error.code().as_deref(), error.constraint()) {
        (
            Some("23505"),
            Some("end_users_subject_owner_conflict" | "end_users_historical_uuid_reuse"),
        ) => (
            StatusCode::CONFLICT,
            "conflict",
            "Subject ownership conflict",
        ),
        (Some("23514"), Some("subject_ownership_namespace_pending")) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Subject namespace unavailable",
        ),
        _ => return None,
    };
    Some(error_response(
        status,
        code,
        message,
        None,
        Some(request_id),
    ))
}
