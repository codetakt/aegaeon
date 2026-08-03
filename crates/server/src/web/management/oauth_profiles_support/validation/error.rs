use super::super::super::error_response;
use axum::{http::StatusCode, response::Response};

pub(super) fn invalid_request(request_id: &str, description: impl AsRef<str>) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        description.as_ref(),
        None,
        Some(request_id),
    )
}
