use super::super::super::super::error_response;
use axum::{http::StatusCode, response::Response};
use serde_json::Value;

pub(super) fn normalized_trust_anchor_entity_id(
    entity_id: &str,
    request_id: &str,
) -> Result<String, Response> {
    let entity_id = entity_id.trim().to_string();
    if crate::federation::validate_entity_url(&entity_id).is_err() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "entity_id must be a valid HTTPS URL with a host",
            None,
            Some(request_id),
        ));
    }

    Ok(entity_id)
}

pub(super) fn validate_trust_anchor_jwks(jwks: &Value, request_id: &str) -> Result<(), Response> {
    if jwks.is_object() && jwks.get("keys").is_some_and(Value::is_array) {
        return Ok(());
    }

    Err(error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "jwks must be a JSON object with a \"keys\" array",
        None,
        Some(request_id),
    ))
}
