use crate::management::types::PolicyDocument;

use super::NumericPolicyField;

pub(super) fn session_and_upstream_fields(policy: &PolicyDocument) -> [NumericPolicyField; 11] {
    [
        ("auth_session_ttl_seconds", policy.auth_session_ttl_seconds),
        ("auth_max_sessions", policy.auth_max_sessions),
        (
            "stepup_challenge_ttl_seconds",
            policy.stepup_challenge_ttl_seconds,
        ),
        (
            "upstream_auth_ttl_seconds",
            policy.upstream_auth_ttl_seconds,
        ),
        (
            "upstream_logout_relay_ttl_seconds",
            policy.upstream_logout_relay_ttl_seconds,
        ),
        (
            "upstream_discovery_cache_ttl_seconds",
            policy.upstream_discovery_cache_ttl_seconds,
        ),
        (
            "upstream_discovery_cache_max_entries",
            policy.upstream_discovery_cache_max_entries,
        ),
        (
            "upstream_jwks_cache_ttl_seconds",
            policy.upstream_jwks_cache_ttl_seconds,
        ),
        (
            "upstream_jwks_cache_max_entries",
            policy.upstream_jwks_cache_max_entries,
        ),
        ("cleanup_interval_seconds", policy.cleanup_interval_seconds),
        (
            "runtime_config_monitor_interval_seconds",
            policy.runtime_config_monitor_interval_seconds,
        ),
    ]
}
