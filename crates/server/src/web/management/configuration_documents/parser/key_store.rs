use super::super::super::{error_response, key_stores};
use axum::{http::StatusCode, response::Response};

pub(super) fn parse_configuration_key_store(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<(String, serde_json::Value, bool), Response> {
    let Some(key_store) = configuration_document
        .get("keyStore")
        .and_then(serde_json::Value::as_object)
    else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.keyStore is required",
            None,
            Some(request_id),
        ));
    };

    let key_store_type = key_store
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim();
    if key_store_type.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.keyStore.type is required",
            None,
            Some(request_id),
        ));
    }
    let key_store_type = key_stores::normalize_key_store_type(key_store_type, request_id)?;

    let Some(key_store_configuration) = key_store.get("configuration") else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.keyStore.configuration is required",
            None,
            Some(request_id),
        ));
    };
    let key_store_configuration = key_stores::validate_key_store_public_configuration(
        key_store_configuration,
        &key_store_type,
        request_id,
    )?;

    Ok((
        key_store_type,
        key_store_configuration,
        key_store
            .get("redacted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
    ))
}
