use super::super::super::normalize_lower_list;
use super::super::input::OAuthProfileInput;
use super::error::invalid_request;
use axum::response::Response;

pub(super) fn normalize_required_scalars(
    input: &mut OAuthProfileInput,
    request_id: &str,
) -> Result<(), Response> {
    input.name = input.name.trim().to_string();
    if input.name.is_empty() {
        return Err(invalid_request(request_id, "name is required"));
    }

    input.profile_type = input.profile_type.trim().to_ascii_uppercase();
    if !matches!(input.profile_type.as_str(), "DOWNSTREAM" | "UPSTREAM") {
        return Err(invalid_request(
            request_id,
            "profileType must be DOWNSTREAM or UPSTREAM",
        ));
    }

    input.sender_constrained = input.sender_constrained.trim().to_ascii_uppercase();
    if !matches!(input.sender_constrained.as_str(), "NONE" | "DPOP" | "MTLS") {
        return Err(invalid_request(
            request_id,
            "senderConstrained must be NONE, DPOP, or MTLS",
        ));
    }

    Ok(())
}

pub(super) fn normalize_allowed_lists(input: &mut OAuthProfileInput) {
    input.allowed_grant_types = normalize_lower_list(&input.allowed_grant_types);
    input.token_endpoint_auth_methods_allowed =
        normalize_lower_list(&input.token_endpoint_auth_methods_allowed);
}

pub(super) fn validate_required_lists(
    input: &OAuthProfileInput,
    request_id: &str,
) -> Result<(), Response> {
    if input.allowed_grant_types.is_empty() {
        return Err(invalid_request(
            request_id,
            "allowedGrantTypes must not be empty",
        ));
    }
    if input.token_endpoint_auth_methods_allowed.is_empty() {
        return Err(invalid_request(
            request_id,
            "tokenEndpointAuthMethodsAllowed must not be empty",
        ));
    }

    Ok(())
}
