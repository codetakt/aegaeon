use super::super::super::error_response;
use crate::management::types::PolicyDocument;
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management) fn validate_federation_policy_for_environment(
    policy: &PolicyDocument,
    _issuer_url: &str,
    request_id: &str,
) -> Result<(), Response> {
    crate::federation::normalize_federation_outbound_allowed_domains(
        &policy.federation_outbound_allowed_domains,
    )
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "federationOutboundAllowedDomains entries must be unique plain DNS domains",
            None,
            Some(request_id),
        )
    })?;
    crate::upstream::normalize_upstream_outbound_allowed_domains(
        &policy.upstream_outbound_allowed_domains,
    )
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "upstreamOutboundAllowedDomains entries must be unique plain DNS domains",
            None,
            Some(request_id),
        )
    })?;

    Ok(())
}
