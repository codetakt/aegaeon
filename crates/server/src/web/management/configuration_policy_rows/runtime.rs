use super::decoder::PolicyRowDecoder;
use axum::response::Response;

pub(super) struct RuntimePolicyFields {
    pub(super) crypto_profile: String,
    pub(super) allowed_signing_algorithms: Vec<String>,
    pub(super) allowed_grant_types: Vec<String>,
    pub(super) access_token_time_to_live_seconds: u32,
    pub(super) id_token_time_to_live_seconds: u32,
    pub(super) refresh_token_time_to_live_seconds: u32,
    pub(super) authorization_code_time_to_live_seconds: u32,
    pub(super) auth_session_ttl_seconds: u32,
    pub(super) auth_max_sessions: u32,
    pub(super) stepup_challenge_ttl_seconds: u32,
    pub(super) upstream_auth_ttl_seconds: u32,
    pub(super) upstream_logout_relay_ttl_seconds: u32,
    pub(super) upstream_discovery_cache_ttl_seconds: u32,
    pub(super) upstream_discovery_cache_max_entries: u32,
    pub(super) upstream_jwks_cache_ttl_seconds: u32,
    pub(super) upstream_jwks_cache_max_entries: u32,
    pub(super) cleanup_interval_seconds: u32,
    pub(super) runtime_config_monitor_interval_seconds: u32,
}

pub(super) fn read_runtime_policy_fields(
    decoder: &PolicyRowDecoder<'_>,
) -> Result<RuntimePolicyFields, Response> {
    Ok(RuntimePolicyFields {
        crypto_profile: decoder.string_field("crypto_profile")?,
        allowed_signing_algorithms: decoder.vec_field("allowed_signing_algorithms")?,
        allowed_grant_types: decoder.vec_field("allowed_grant_types")?,
        access_token_time_to_live_seconds: decoder
            .seconds_field("access_token_time_to_live_seconds", 1)?,
        id_token_time_to_live_seconds: decoder.seconds_field("id_token_time_to_live_seconds", 1)?,
        refresh_token_time_to_live_seconds: decoder
            .seconds_field("refresh_token_time_to_live_seconds", 1)?,
        authorization_code_time_to_live_seconds: decoder
            .seconds_field("authorization_code_time_to_live_seconds", 1)?,
        auth_session_ttl_seconds: decoder.seconds_field("auth_session_ttl_seconds", 1)?,
        auth_max_sessions: decoder.u32_field("auth_max_sessions", 1)?,
        stepup_challenge_ttl_seconds: decoder.seconds_field("stepup_challenge_ttl_seconds", 1)?,
        upstream_auth_ttl_seconds: decoder.seconds_field("upstream_auth_ttl_seconds", 1)?,
        upstream_logout_relay_ttl_seconds: decoder
            .seconds_field("upstream_logout_relay_ttl_seconds", 1)?,
        upstream_discovery_cache_ttl_seconds: decoder
            .seconds_field("upstream_discovery_cache_ttl_seconds", 1)?,
        upstream_discovery_cache_max_entries: decoder
            .u32_field("upstream_discovery_cache_max_entries", 1)?,
        upstream_jwks_cache_ttl_seconds: decoder
            .seconds_field("upstream_jwks_cache_ttl_seconds", 1)?,
        upstream_jwks_cache_max_entries: decoder.u32_field("upstream_jwks_cache_max_entries", 1)?,
        cleanup_interval_seconds: decoder.seconds_field("cleanup_interval_seconds", 1)?,
        runtime_config_monitor_interval_seconds: decoder
            .seconds_field("runtime_config_monitor_interval_seconds", 1)?,
    })
}
