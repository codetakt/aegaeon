use super::{i32_from_u32_field, PolicyUpdateQuery};
use crate::management::types::PolicyDocument;
use axum::response::Response;

pub(super) fn bind_allowlists_ttls_and_acr_policy<'q>(
    query: PolicyUpdateQuery<'q>,
    policy: &'q PolicyDocument,
    request_id: &str,
) -> Result<PolicyUpdateQuery<'q>, Response> {
    Ok(query
        .bind(policy.crypto_profile.clone())
        .bind(policy.allowed_signing_algorithms.clone())
        .bind(policy.allowed_grant_types.clone())
        .bind(i32_from_u32_field(
            "access_token_time_to_live_seconds",
            policy.access_token_time_to_live_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "id_token_time_to_live_seconds",
            policy.id_token_time_to_live_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "refresh_token_time_to_live_seconds",
            policy.refresh_token_time_to_live_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "authorization_code_time_to_live_seconds",
            policy.authorization_code_time_to_live_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "stepup_challenge_ttl_seconds",
            policy.stepup_challenge_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "upstream_auth_ttl_seconds",
            policy.upstream_auth_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "upstream_logout_relay_ttl_seconds",
            policy.upstream_logout_relay_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "upstream_discovery_cache_ttl_seconds",
            policy.upstream_discovery_cache_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "upstream_jwks_cache_ttl_seconds",
            policy.upstream_jwks_cache_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "cleanup_interval_seconds",
            policy.cleanup_interval_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "runtime_config_monitor_interval_seconds",
            policy.runtime_config_monitor_interval_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "auth_session_ttl_seconds",
            policy.auth_session_ttl_seconds,
            request_id,
        )?)
        .bind(i32_from_u32_field(
            "auth_max_sessions",
            policy.auth_max_sessions,
            request_id,
        )?)
        .bind(policy.authorization_details_types_supported.clone())
        .bind(policy.acr_values_supported.clone())
        .bind(policy.default_acr.clone())
        .bind(policy.local_password_acr.clone()))
}
