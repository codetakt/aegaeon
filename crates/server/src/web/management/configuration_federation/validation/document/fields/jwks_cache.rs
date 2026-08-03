use super::super::urls::validate_https_url_field;
use super::scalar::{require_positive_integer_field, required_string_field};
use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};
use serde_json::{Map, Value};

pub(super) fn validate_optional_jwks_cache(
    federation: &Map<String, Value>,
    request_id: &str,
) -> Result<(), Response> {
    let Some(jwks_cache) = federation.get("jwksCache") else {
        return Ok(());
    };
    let jwks_cache = jwks_cache.as_object().ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.federation.jwksCache must be an object",
            None,
            Some(request_id),
        )
    })?;
    let jwks_uri = required_string_field(
        jwks_cache,
        "jwksUri",
        "configurationDocument.federation.jwksCache.jwksUri is required",
        request_id,
    )?;
    let _ = validate_https_url_field(
        "configurationDocument.federation.jwksCache.jwksUri",
        jwks_uri,
        request_id,
    )?;
    require_positive_integer_field(
        jwks_cache,
        "maxAgeSeconds",
        "configurationDocument.federation.jwksCache.maxAgeSeconds must be a positive integer",
        request_id,
    )
}
