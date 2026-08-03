use axum::{http::StatusCode, response::Response};

use super::super::super::error_response;

pub(in crate::web::management) fn normalize_key_store_audit_note(
    value: Option<&str>,
    field: &str,
    request_id: &str,
) -> Result<Option<String>, Response> {
    let Some(trimmed) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if trimmed.len() > 1024 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!("{field} must be at most 1024 bytes"),
            None,
            Some(request_id),
        ));
    }

    Ok(Some(trimmed.to_string()))
}
