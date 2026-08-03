use super::super::super::error_response;
use axum::{http::StatusCode, response::Response};
use std::collections::BTreeSet;

pub(in crate::web::management) fn parse_configuration_scope_allowlist(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<Vec<String>, Response> {
    let Some(value) = configuration_document.get("scopeAllowlist") else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.scopeAllowlist must be an array",
            None,
            Some(request_id),
        ));
    };

    let mut seen = BTreeSet::new();
    let mut scopes = Vec::with_capacity(items.len());
    for item in items {
        let Some(scope) = item.as_str().map(str::trim) else {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "configurationDocument.scopeAllowlist entries must be strings",
                None,
                Some(request_id),
            ));
        };
        if scope.is_empty() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "configurationDocument.scopeAllowlist entries must not be blank",
                None,
                Some(request_id),
            ));
        }
        if !crate::oauth_scope::is_scope_token(scope) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "configurationDocument.scopeAllowlist entries must be RFC 6749 scope-token values",
                None,
                Some(request_id),
            ));
        }
        if !seen.insert(scope.to_string()) {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "configurationDocument.scopeAllowlist entries must be unique",
                None,
                Some(request_id),
            ));
        }
        scopes.push(scope.to_string());
    }
    Ok(scopes)
}
