use axum::{http::StatusCode, response::Response};

use super::super::super::error_response;

pub(in crate::web::management) fn oauth_profile_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "OAuth profile not found",
        None,
        Some(request_id),
    )
}
