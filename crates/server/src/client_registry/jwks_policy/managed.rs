use crate::config::ConfigError;
use crate::management::types::PolicyDocument;

use super::{
    valid_jwks_cache_gc_interval_secs, valid_jwks_cache_ttl_secs, valid_jwks_circuit_open_fails,
    valid_jwks_circuit_reset_secs, valid_jwks_http_retries, valid_jwks_http_timeout_secs,
    valid_jwks_local_cache_max_entries, valid_jwks_max_body_bytes, valid_jwks_refresh_skew_secs,
    MAX_JWKS_CACHE_TTL_SECS,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct JwksManagedRuntimePolicy {
    pub(super) allow_kid_reuse: bool,
    pub(super) circuit_open_fails: u32,
    pub(super) circuit_reset_secs: u64,
    pub(super) cache_ttl_secs: u64,
    pub(super) cache_gc_interval_secs: u64,
    pub(super) http_timeout_secs: u64,
    pub(super) refresh_skew_secs: u64,
    pub(super) shared_state_max_age_secs: u64,
    pub(super) local_cache_max_entries: u32,
    pub(super) max_body_bytes: usize,
    pub(super) http_retries: u32,
}

impl Default for JwksManagedRuntimePolicy {
    fn default() -> Self {
        Self {
            allow_kid_reuse: false,
            circuit_open_fails: 3,
            circuit_reset_secs: 30,
            cache_ttl_secs: 300,
            cache_gc_interval_secs: 600,
            http_timeout_secs: 5,
            refresh_skew_secs: 10,
            shared_state_max_age_secs: MAX_JWKS_CACHE_TTL_SECS,
            local_cache_max_entries: super::DEFAULT_JWKS_LOCAL_CACHE_MAX_ENTRIES as u32,
            max_body_bytes: 64 * 1024,
            http_retries: 2,
        }
    }
}

impl JwksManagedRuntimePolicy {
    pub(super) fn try_from_management_policy(policy: &PolicyDocument) -> Result<Self, ConfigError> {
        Ok(Self {
            allow_kid_reuse: policy.jwks_allow_kid_reuse,
            circuit_open_fails: validate_u32(
                "jwks_circuit_open_fails",
                policy.jwks_circuit_open_fails,
                valid_jwks_circuit_open_fails,
                "a value in 1..=1000",
            )?,
            circuit_reset_secs: validate_u64(
                "jwks_circuit_reset_seconds",
                u64::from(policy.jwks_circuit_reset_seconds),
                valid_jwks_circuit_reset_secs,
                "a value in 1..=3600 seconds",
            )?,
            cache_ttl_secs: validate_u64(
                "jwks_cache_ttl_seconds",
                u64::from(policy.jwks_cache_ttl_seconds),
                valid_jwks_cache_ttl_secs,
                "a value in 1..=86400 seconds",
            )?,
            cache_gc_interval_secs: validate_u64(
                "jwks_cache_gc_interval_seconds",
                u64::from(policy.jwks_cache_gc_interval_seconds),
                valid_jwks_cache_gc_interval_secs,
                "a value in 1..=86400 seconds",
            )?,
            http_timeout_secs: validate_u64(
                "jwks_http_timeout_seconds",
                u64::from(policy.jwks_http_timeout_seconds),
                valid_jwks_http_timeout_secs,
                "a value in 1..=60 seconds",
            )?,
            refresh_skew_secs: validate_u64(
                "jwks_refresh_skew_seconds",
                u64::from(policy.jwks_refresh_skew_seconds),
                valid_jwks_refresh_skew_secs,
                "a value in 0..=3600 seconds",
            )?,
            shared_state_max_age_secs: validate_u64(
                "jwks_shared_state_max_age_seconds",
                u64::from(policy.jwks_shared_state_max_age_seconds),
                valid_jwks_cache_ttl_secs,
                "a value in 1..=86400 seconds",
            )?,
            local_cache_max_entries: validate_u32(
                "jwks_local_cache_max_entries",
                policy.jwks_local_cache_max_entries,
                valid_jwks_local_cache_max_entries,
                "a value in 1..=1000000 entries",
            )?,
            max_body_bytes: validate_usize(
                "jwks_max_body_bytes",
                policy.jwks_max_body_bytes as usize,
                valid_jwks_max_body_bytes,
                "a value in 1..=16777216 bytes",
            )?,
            http_retries: validate_u32(
                "jwks_http_retries",
                policy.jwks_http_retries,
                valid_jwks_http_retries,
                "a value in 0..=10",
            )?,
        })
    }
}

fn validate_u64(
    key: &str,
    value: u64,
    is_valid: fn(u64) -> bool,
    expectation: &str,
) -> Result<u64, ConfigError> {
    if is_valid(value) {
        Ok(value)
    } else {
        Err(ConfigError::InvalidNumberRange {
            key: key.to_string(),
            value: value.to_string(),
            expectation: expectation.to_string(),
        })
    }
}

fn validate_u32(
    key: &str,
    value: u32,
    is_valid: fn(u32) -> bool,
    expectation: &str,
) -> Result<u32, ConfigError> {
    if is_valid(value) {
        Ok(value)
    } else {
        Err(ConfigError::InvalidNumberRange {
            key: key.to_string(),
            value: value.to_string(),
            expectation: expectation.to_string(),
        })
    }
}

fn validate_usize(
    key: &str,
    value: usize,
    is_valid: fn(usize) -> bool,
    expectation: &str,
) -> Result<usize, ConfigError> {
    if is_valid(value) {
        Ok(value)
    } else {
        Err(ConfigError::InvalidNumberRange {
            key: key.to_string(),
            value: value.to_string(),
            expectation: expectation.to_string(),
        })
    }
}
