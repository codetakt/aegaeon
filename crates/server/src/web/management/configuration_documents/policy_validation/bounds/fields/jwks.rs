use crate::management::types::PolicyDocument;

use super::NumericPolicyField;

pub(super) fn jwks_fields(policy: &PolicyDocument) -> [NumericPolicyField; 10] {
    [
        ("jwks_circuit_open_fails", policy.jwks_circuit_open_fails),
        (
            "jwks_circuit_reset_seconds",
            policy.jwks_circuit_reset_seconds,
        ),
        ("jwks_cache_ttl_seconds", policy.jwks_cache_ttl_seconds),
        (
            "jwks_cache_gc_interval_seconds",
            policy.jwks_cache_gc_interval_seconds,
        ),
        (
            "jwks_local_cache_max_entries",
            policy.jwks_local_cache_max_entries,
        ),
        (
            "jwks_http_timeout_seconds",
            policy.jwks_http_timeout_seconds,
        ),
        (
            "jwks_refresh_skew_seconds",
            policy.jwks_refresh_skew_seconds,
        ),
        (
            "jwks_shared_state_max_age_seconds",
            policy.jwks_shared_state_max_age_seconds,
        ),
        ("jwks_max_body_bytes", policy.jwks_max_body_bytes),
        ("jwks_http_retries", policy.jwks_http_retries),
    ]
}
