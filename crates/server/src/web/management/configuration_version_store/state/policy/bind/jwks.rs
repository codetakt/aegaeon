use super::{i32_from_u32_field, PolicyUpdateQuery};
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(super) fn bind_jwks_policy<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    Ok(query
        .bind(policy.jwks_allow_kid_reuse)
        .bind(i32_from_u32_field(
            "jwks_circuit_open_fails",
            policy.jwks_circuit_open_fails,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "jwks_circuit_reset_seconds",
            policy.jwks_circuit_reset_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "jwks_cache_ttl_seconds",
            policy.jwks_cache_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "jwks_cache_gc_interval_seconds",
            policy.jwks_cache_gc_interval_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "jwks_http_timeout_seconds",
            policy.jwks_http_timeout_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "jwks_refresh_skew_seconds",
            policy.jwks_refresh_skew_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "jwks_shared_state_max_age_seconds",
            policy.jwks_shared_state_max_age_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "jwks_max_body_bytes",
            policy.jwks_max_body_bytes,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "jwks_http_retries",
            policy.jwks_http_retries,
            request_id,
        )?))
}
