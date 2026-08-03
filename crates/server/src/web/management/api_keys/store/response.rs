use axum::{http::StatusCode, response::Response};

use crate::web::management::error_response;

pub(in crate::web::management::api_keys) fn api_key_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "API key not found or already revoked",
        None,
        Some(request_id),
    )
}
