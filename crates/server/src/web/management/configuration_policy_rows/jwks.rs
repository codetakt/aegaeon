use super::decoder::PolicyRowDecoder;
use axum::response::Response;

pub(super) struct JwksPolicyFields {
    pub(super) jwks_allow_kid_reuse: bool,
    pub(super) jwks_circuit_open_fails: u32,
    pub(super) jwks_circuit_reset_seconds: u32,
    pub(super) jwks_cache_ttl_seconds: u32,
    pub(super) jwks_cache_gc_interval_seconds: u32,
    pub(super) jwks_local_cache_max_entries: u32,
    pub(super) jwks_http_timeout_seconds: u32,
    pub(super) jwks_refresh_skew_seconds: u32,
    pub(super) jwks_shared_state_max_age_seconds: u32,
    pub(super) jwks_max_body_bytes: u32,
    pub(super) jwks_http_retries: u32,
}

pub(super) fn read_jwks_policy_fields(
    decoder: &PolicyRowDecoder<'_>,
) -> Result<JwksPolicyFields, Response> {
    Ok(JwksPolicyFields {
        jwks_allow_kid_reuse: decoder.bool_field("jwks_allow_kid_reuse")?,
        jwks_circuit_open_fails: decoder.seconds_field("jwks_circuit_open_fails", 1)?,
        jwks_circuit_reset_seconds: decoder.seconds_field("jwks_circuit_reset_seconds", 1)?,
        jwks_cache_ttl_seconds: decoder.seconds_field("jwks_cache_ttl_seconds", 1)?,
        jwks_cache_gc_interval_seconds: decoder
            .seconds_field("jwks_cache_gc_interval_seconds", 1)?,
        jwks_local_cache_max_entries: decoder.u32_field("jwks_local_cache_max_entries", 1)?,
        jwks_http_timeout_seconds: decoder.seconds_field("jwks_http_timeout_seconds", 1)?,
        jwks_refresh_skew_seconds: decoder.seconds_field("jwks_refresh_skew_seconds", 0)?,
        jwks_shared_state_max_age_seconds: decoder
            .seconds_field("jwks_shared_state_max_age_seconds", 1)?,
        jwks_max_body_bytes: decoder.u32_field("jwks_max_body_bytes", 1)?,
        jwks_http_retries: decoder.u32_field("jwks_http_retries", 0)?,
    })
}
