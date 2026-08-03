use super::super::super::input::OAuthProfileInput;
use super::super::error::invalid_request;
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(in crate::web::management::oauth_profiles_support::validation) fn validate_policy_required_flags(
    input: &OAuthProfileInput,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    if policy.pkce_required && !input.require_pkce {
        return Err(invalid_request(
            request_id,
            "requirePkce must be true when PKCE is required by policy",
        ));
    }
    if policy.require_state_parameter && !input.require_state_parameter {
        return Err(invalid_request(
            request_id,
            "requireStateParameter must be true when state is required by policy",
        ));
    }

    Ok(())
}
