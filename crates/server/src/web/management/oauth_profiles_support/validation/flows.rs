use super::super::input::OAuthProfileInput;
use super::error::invalid_request;
use crate::policy::validate_supported_grant_types;
use axum::response::Response;

pub(super) fn validate_profile_security_floor(
    input: &OAuthProfileInput,
    request_id: &str,
) -> Result<(), Response> {
    if !input.require_pkce {
        return Err(invalid_request(request_id, "OAuth profiles require PKCE"));
    }

    Ok(())
}

pub(super) fn validate_ropc_flow(
    input: &OAuthProfileInput,
    request_id: &str,
) -> Result<(), Response> {
    if input
        .allowed_grant_types
        .iter()
        .any(|grant| grant == "password")
    {
        return Err(invalid_request(
            request_id,
            "allowedGrantTypes cannot include password",
        ));
    }

    Ok(())
}

pub(super) fn validate_supported_grant_type_policy(
    input: &OAuthProfileInput,
    request_id: &str,
) -> Result<(), Response> {
    validate_supported_grant_types(&input.allowed_grant_types)
        .map_err(|error| invalid_request(request_id, error.to_string()))
}
