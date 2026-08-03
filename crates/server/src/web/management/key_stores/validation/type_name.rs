use axum::{http::StatusCode, response::Response};

use super::super::super::error_response;

pub(in crate::web::management) fn normalize_key_store_type(
    raw: &str,
    request_id: &str,
) -> Result<String, Response> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "key store type is required",
            None,
            Some(request_id),
        ));
    }
    if trimmed != "databaseEncrypted" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unsupported key store type",
            Some(serde_json::json!({
                "supportedTypes": ["databaseEncrypted"],
            })),
            Some(request_id),
        ));
    }

    Ok(trimmed.to_string())
}
