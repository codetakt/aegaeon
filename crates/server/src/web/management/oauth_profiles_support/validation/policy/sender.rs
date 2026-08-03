use super::super::super::input::OAuthProfileInput;
use super::super::error::invalid_request;
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(in crate::web::management::oauth_profiles_support::validation) fn validate_sender_constraints(
    input: &OAuthProfileInput,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    if input.enforce_refresh_sender_binding && input.sender_constrained == "NONE" {
        return Err(invalid_request(
            request_id,
            "senderConstrained must not be NONE when refresh binding enforcement is enabled",
        ));
    }
    if policy.dcr_require_sender_constrained && input.sender_constrained == "NONE" {
        return Err(invalid_request(
            request_id,
            "senderConstrained must not be NONE when sender-constrained tokens are required by policy",
        ));
    }

    Ok(())
}
