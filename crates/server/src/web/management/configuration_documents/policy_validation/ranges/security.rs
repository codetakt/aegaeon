use axum::response::Response;

use crate::client_registry::JwksRuntimePolicy;
use crate::config::{
    valid_client_assertion_replay_window_secs, valid_dpop_iat_window_secs,
    valid_dpop_nonce_ttl_secs, valid_jwt_introspection_exp_secs, valid_request_object_jti_ttl_secs,
};
use crate::management::types::PolicyDocument;

use super::invalid_request;

pub(in crate::web::management::configuration_documents::policy_validation) fn validate_security_and_replay_ranges(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    if !valid_client_assertion_replay_window_secs(i64::from(policy.pkjwt_jti_window_seconds)) {
        return Err(invalid_request(
            "Client assertion replay window exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_client_assertion_replay_window_secs(i64::from(policy.jwt_bearer_jti_window_seconds)) {
        return Err(invalid_request(
            "JWT bearer assertion replay window exceeds the supported policy range",
            request_id,
        ));
    }
    if JwksRuntimePolicy::validate_management_policy(policy).is_err() {
        return Err(invalid_request(
            "JWKS runtime policy exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_request_object_jti_ttl_secs(u64::from(policy.request_object_jti_ttl_seconds)) {
        return Err(invalid_request(
            "Request Object jti replay window exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_jwt_introspection_exp_secs(u64::from(policy.jwt_introspection_exp_seconds)) {
        return Err(invalid_request(
            "JWT introspection response lifetime exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_dpop_iat_window_secs(u64::from(policy.dpop_iat_window_seconds)) {
        return Err(invalid_request(
            "DPoP iat window exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_dpop_nonce_ttl_secs(u64::from(policy.dpop_nonce_ttl_seconds)) {
        return Err(invalid_request(
            "DPoP nonce TTL exceeds the supported policy range",
            request_id,
        ));
    }

    Ok(())
}
