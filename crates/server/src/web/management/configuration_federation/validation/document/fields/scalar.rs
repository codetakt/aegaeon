use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};
use serde_json::{Map, Value};

pub(super) fn required_string_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    message: &str,
    request_id: &str,
) -> Result<&'a str, Response> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                None,
                Some(request_id),
            )
        })
}

pub(super) fn require_positive_integer_field(
    object: &Map<String, Value>,
    key: &str,
    message: &str,
    request_id: &str,
) -> Result<(), Response> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .map(|_| ())
        .ok_or_else(|| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                None,
                Some(request_id),
            )
        })
}
