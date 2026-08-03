mod acr;
mod bounds;
mod ranges;

use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(in crate::web::management) fn validate_patched_policy(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    bounds::validate_sql_integer_bounds(policy, request_id)?;
    ranges::validate_allowlists_and_token_ttls(policy, request_id)?;
    ranges::validate_dcr_sender_methods(policy, request_id)?;
    ranges::validate_session_and_protocol_ranges(policy, request_id)?;
    ranges::validate_security_and_replay_ranges(policy, request_id)?;
    ranges::validate_upstream_and_federation_ranges(policy, request_id)?;
    ranges::validate_mtls_base_url(policy, request_id)?;
    crate::config::validate_management_policy_for_runtime(policy)
        .map_err(|error| ranges::invalid_request(&error.to_string(), request_id))?;
    acr::validate_acr_values(policy, request_id)
}
