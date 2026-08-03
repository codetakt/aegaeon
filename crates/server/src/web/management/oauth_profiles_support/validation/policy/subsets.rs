use super::super::super::super::normalize_lower_list;
use super::super::super::input::OAuthProfileInput;
use super::super::error::invalid_request;
use crate::dcr::runtime_supported_sender_constrained_method;
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(in crate::web::management::oauth_profiles_support::validation) fn validate_policy_subsets(
    input: &OAuthProfileInput,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    validate_grant_type_subset(input, policy, request_id)?;
    validate_sender_method_policy(input, policy, request_id)
}

fn validate_grant_type_subset(
    input: &OAuthProfileInput,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    let policy_allowed_grant_types = normalize_lower_list(&policy.allowed_grant_types);
    if input
        .allowed_grant_types
        .iter()
        .any(|grant| !policy_allowed_grant_types.contains(grant))
    {
        return Err(invalid_request(
            request_id,
            "allowedGrantTypes must be a subset of the environment policy",
        ));
    }

    Ok(())
}

fn validate_sender_method_policy(
    input: &OAuthProfileInput,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    if input.sender_constrained == "NONE" {
        return Ok(());
    }

    let sender_method = input.sender_constrained.to_ascii_lowercase();
    if !runtime_supported_sender_constrained_method(&sender_method) {
        return Err(invalid_request(
            request_id,
            "senderConstrained method is not implemented for DCR profiles",
        ));
    }
    let policy_sender_methods = normalize_lower_list(&policy.dcr_allowed_sender_methods);
    if !policy_sender_methods.contains(&sender_method) {
        return Err(invalid_request(
            request_id,
            "senderConstrained must be allowed by environment policy",
        ));
    }

    Ok(())
}
