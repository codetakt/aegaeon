use super::super::super::super::error_response;
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management::runtime_keys::lifecycle::workflows) fn runtime_key_not_found(
    request_id: &str,
    message: &str,
) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        message,
        None,
        Some(request_id),
    )
}
