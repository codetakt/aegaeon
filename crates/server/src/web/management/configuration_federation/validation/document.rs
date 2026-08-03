mod fields;
mod policies;
mod secrets;
mod urls;

use super::super::super::error_response;
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management) fn validate_configuration_document_federation(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<(), Response> {
    let Some(federation_value) = configuration_document.get("federation") else {
        return Ok(());
    };
    let federation = federation_value.as_object().ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "configurationDocument.federation must be an object",
            None,
            Some(request_id),
        )
    })?;
    crate::runtime_configuration::parse_federation_document_value(federation_value).map_err(
        |_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "configurationDocument.federation must be a strict federation configuration object",
                None,
                Some(request_id),
            )
        },
    )?;

    secrets::ensure_no_embedded_federation_secrets(federation, request_id)?;
    fields::validate_federation_core_fields(federation, request_id)?;
    fields::validate_optional_jwks_cache(federation, request_id)?;
    policies::validate_federation_policy_blocks(configuration_document, request_id)
}
