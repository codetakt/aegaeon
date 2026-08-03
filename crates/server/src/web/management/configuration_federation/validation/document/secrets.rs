use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};
use serde_json::{Map, Value};

pub(super) fn ensure_no_embedded_federation_secrets(
    federation: &Map<String, Value>,
    request_id: &str,
) -> Result<(), Response> {
    if let Some(forbidden_key) = find_forbidden_federation_secret_key_in_object(federation) {
        let details = serde_json::json!({ "field": forbidden_key });
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.federation must not embed secrets; use keystore references instead",
            Some(details),
            Some(request_id),
        ));
    }
    Ok(())
}

fn find_forbidden_federation_secret_key(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => find_forbidden_federation_secret_key_in_object(map),
        Value::Array(items) => items.iter().find_map(find_forbidden_federation_secret_key),
        _ => None,
    }
}

fn find_forbidden_federation_secret_key_in_object(object: &Map<String, Value>) -> Option<String> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "clientSecret",
        "client_secret",
        "privateKey",
        "private_key",
        "privateKeyPem",
        "private_key_pem",
    ];

    object.iter().find_map(|(key, nested)| {
        FORBIDDEN_KEYS
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
            .then(|| key.clone())
            .or_else(|| find_forbidden_federation_secret_key(nested))
    })
}
