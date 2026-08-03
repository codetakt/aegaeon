use axum::{http::StatusCode, response::Response};

use crate::web::management::error_response;

pub(in crate::web::management) fn runtime_key_bad_request(
    request_id: &str,
    message: &str,
    details: Option<serde_json::Value>,
) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        message,
        details,
        Some(request_id),
    )
}
