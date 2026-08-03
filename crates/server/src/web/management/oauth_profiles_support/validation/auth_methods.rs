use super::super::input::OAuthProfileInput;
use super::error::invalid_request;
use crate::management::types::PolicyDocument;
use crate::upstream::upstream_client_auth_method_supported;
use axum::response::Response;
use std::collections::BTreeSet;

pub(super) fn validate_token_endpoint_auth_methods(
    input: &OAuthProfileInput,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    let allowed_auth_methods = BTreeSet::from([
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
        "none",
    ]);
    if input
        .token_endpoint_auth_methods_allowed
        .iter()
        .any(|method| !allowed_auth_methods.contains(method.as_str()))
    {
        return Err(invalid_request(
            request_id,
            "tokenEndpointAuthMethodsAllowed contains unsupported methods",
        ));
    }
    if input.profile_type == "UPSTREAM"
        && input
            .token_endpoint_auth_methods_allowed
            .iter()
            .any(|method| !upstream_client_auth_method_supported(method))
    {
        return Err(invalid_request(
            request_id,
            "upstream OAuth profiles can only allow client_secret_basic, client_secret_post, or none",
        ));
    }
    if token_auth_method_allowed(input, "private_key_jwt") && !policy.private_key_jwt_enabled {
        return Err(invalid_request(
            request_id,
            "private_key_jwt is not enabled by policy",
        ));
    }
    if token_auth_method_allowed(input, "none") && policy.require_client_auth_token {
        return Err(invalid_request(
            request_id,
            "tokenEndpointAuthMethodsAllowed cannot include none when client authentication is required",
        ));
    }

    Ok(())
}

fn token_auth_method_allowed(input: &OAuthProfileInput, method: &str) -> bool {
    input
        .token_endpoint_auth_methods_allowed
        .iter()
        .any(|allowed| allowed == method)
}
