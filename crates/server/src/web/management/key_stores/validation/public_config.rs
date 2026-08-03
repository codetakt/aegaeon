use axum::{http::StatusCode, response::Response};

use super::super::super::error_response;

fn is_sensitive_key_store_public_config_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect();
    [
        "secret",
        "password",
        "token",
        "credential",
        "privatekey",
        "keyhandle",
        "apikey",
        "accesskey",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

pub(in crate::web::management) fn key_store_public_config_contains_sensitive_key(
    value: &serde_json::Value,
) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(key, value)| {
            is_sensitive_key_store_public_config_key(key)
                || key_store_public_config_contains_sensitive_key(value)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(key_store_public_config_contains_sensitive_key),
        _ => false,
    }
}

pub(in crate::web::management) fn validate_key_store_public_configuration(
    configuration: &serde_json::Value,
    key_store_type: &str,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let Some(configuration_object) = configuration.as_object() else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "key store configuration must be a JSON object",
            None,
            Some(request_id),
        ));
    };
    if key_store_public_config_contains_sensitive_key(configuration) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "key store public configuration must not contain secret material",
            None,
            Some(request_id),
        ));
    }
    match key_store_type {
        "databaseEncrypted" if configuration_object.is_empty() => Ok(configuration.clone()),
        "databaseEncrypted" => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "databaseEncrypted key store configuration must be empty",
            None,
            Some(request_id),
        )),
        _ => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unsupported key store type",
            None,
            Some(request_id),
        )),
    }
}
