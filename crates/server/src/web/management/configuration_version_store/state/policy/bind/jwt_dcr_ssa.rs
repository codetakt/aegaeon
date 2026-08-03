use super::{i32_from_u32_field, PolicyUpdateQuery};
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(super) fn bind_jwt_dcr_and_ssa_policy<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    Ok(query
        .bind(policy.jwt_bearer_allow_client_subject)
        .bind(i32_from_u32_field(
            "jwt_bearer_jti_window_seconds",
            policy.jwt_bearer_jti_window_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "request_object_jti_ttl_seconds",
            policy.request_object_jti_ttl_seconds,
            request_id,
        )?)
        .bind(policy.jwt_access_tokens_enabled)
        .bind(policy.jwt_introspection_enabled)
        .bind(i32_from_u32_field(
            "jwt_introspection_exp_seconds",
            policy.jwt_introspection_exp_seconds,
            request_id,
        )?)
        .bind(policy.dcr_require_pkce_for_public)
        .bind(policy.dcr_require_pkce_for_confidential)
        .bind(policy.dcr_require_sender_constrained)
        .bind(policy.dcr_allowed_sender_methods.clone())
        .bind(policy.ssa_jwt_pem.clone())
        .bind(policy.ssa_expected_iss.clone())
        .bind(policy.ssa_expected_aud.clone())
        .bind(i32_from_u32_field(
            "ssa_leeway_seconds",
            policy.ssa_leeway_seconds,
            request_id,
        )?))
}
