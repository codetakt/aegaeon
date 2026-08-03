use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};

pub(super) fn validate_federation_policy_blocks(
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<(), Response> {
    let attribute_mappings = crate::upstream::parse_upstream_attribute_mappings(
        configuration_document.get("federation"),
    )
    .map_err(|message| invalid_federation_policy_response(&message, request_id))?;

    crate::upstream::parse_upstream_claim_release_policy(
        configuration_document.get("federation"),
        &attribute_mappings,
    )
    .map_err(|message| invalid_federation_policy_response(&message, request_id))?;

    crate::upstream::parse_upstream_jit_provisioning_policy(
        configuration_document.get("federation"),
    )
    .map_err(|message| invalid_federation_policy_response(&message, request_id))?;
    crate::upstream::parse_upstream_logout_policy(configuration_document.get("federation"))
        .map_err(|message| invalid_federation_policy_response(&message, request_id))?;

    Ok(())
}

fn invalid_federation_policy_response(message: &str, request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        message,
        None,
        Some(request_id),
    )
}
