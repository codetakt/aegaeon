mod auth_methods;
mod error;
mod flows;
mod normalization;
mod policy;

use super::input::OAuthProfileInput;
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(in crate::web::management) fn validate_oauth_profile_input(
    input: &mut OAuthProfileInput,
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    normalization::normalize_required_scalars(input, request_id)?;
    normalization::normalize_allowed_lists(input);
    normalization::validate_required_lists(input, request_id)?;
    policy::validate_policy_required_flags(input, policy, request_id)?;
    flows::validate_profile_security_floor(input, request_id)?;
    flows::validate_ropc_flow(input, request_id)?;
    flows::validate_supported_grant_type_policy(input, request_id)?;
    policy::validate_sender_constraints(input, policy, request_id)?;
    policy::validate_policy_subsets(input, policy, request_id)?;
    auth_methods::validate_token_endpoint_auth_methods(input, policy, request_id)
}
