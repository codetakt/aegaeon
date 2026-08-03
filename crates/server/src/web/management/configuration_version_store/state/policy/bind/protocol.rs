use super::{i32_from_u32_field, PolicyUpdateQuery};
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(super) fn bind_protocol_and_client_policy<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    Ok(query
        .bind(policy.pkce_required)
        .bind(policy.dcr_enabled)
        .bind(policy.require_state_parameter)
        .bind(policy.strict_authorize_redirect)
        .bind(policy.require_client_auth_token)
        .bind(policy.require_client_auth_par)
        .bind(policy.require_client_auth_introspection)
        .bind(policy.require_client_auth_revocation)
        .bind(policy.sender_constraint.as_db_str())
        .bind(policy.require_scope_subset)
        .bind(policy.require_audience_match)
        .bind(policy.retain_refresh_chain)
        .bind(policy.enforce_refresh_sender_binding)
        .bind(policy.dpop_strict)
        .bind(i32_from_u32_field(
            "dpop_iat_window_seconds",
            policy.dpop_iat_window_seconds,
            request_id,
        )?)
        .bind(policy.dpop_require_nonce)
        .bind(i32_from_u32_field(
            "dpop_nonce_ttl_seconds",
            policy.dpop_nonce_ttl_seconds,
            request_id,
        )?)
        .bind(policy.require_pushed_authorization_requests)
        .bind(i32_from_u32_field(
            "par_expires_in_seconds",
            policy.par_expires_in_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "device_code_ttl_seconds",
            policy.device_code_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "device_code_poll_interval_seconds",
            policy.device_code_poll_interval_seconds,
            request_id,
        )?)
        .bind(policy.private_key_jwt_enabled)
        .bind(policy.client_jwt_allowed_algs.clone())
        .bind(policy.client_jwt_require_kid)
        .bind(i32_from_u32_field(
            "jwt_leeway_seconds",
            policy.jwt_leeway_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "pkjwt_jti_window_seconds",
            policy.pkjwt_jti_window_seconds,
            request_id,
        )?))
}
