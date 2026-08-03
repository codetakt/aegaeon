use axum::{http::StatusCode, response::Response};
use std::collections::BTreeSet;

pub(super) fn normalize_text(value: &str) -> String {
    value.trim().to_string()
}

pub(super) fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    value.map(normalize_text).filter(|v| !v.is_empty())
}

pub(super) fn invalid_numeric_field_response(field: &str, request_id: &str) -> Response {
    super::error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        &format!("{field} is outside the supported range"),
        None,
        Some(request_id),
    )
}

pub(super) fn i32_from_u32_field(
    field: &str,
    value: u32,
    request_id: &str,
) -> Result<i32, Response> {
    i32::try_from(value).map_err(|_| invalid_numeric_field_response(field, request_id))
}

pub(super) fn normalize_lower_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn normalize_trimmed_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
