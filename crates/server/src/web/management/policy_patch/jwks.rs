use crate::management::types::{PolicyDocument, PolicyPatchRequest};

pub(super) fn apply_jwks_policy_patch(policy: &mut PolicyDocument, patch: &PolicyPatchRequest) {
    if let Some(value) = patch.jwks_allow_kid_reuse {
        policy.jwks_allow_kid_reuse = value;
    }
    if let Some(value) = patch.jwks_circuit_open_fails {
        policy.jwks_circuit_open_fails = value;
    }
    if let Some(value) = patch.jwks_circuit_reset_seconds {
        policy.jwks_circuit_reset_seconds = value;
    }
    if let Some(value) = patch.jwks_cache_ttl_seconds {
        policy.jwks_cache_ttl_seconds = value;
    }
    if let Some(value) = patch.jwks_cache_gc_interval_seconds {
        policy.jwks_cache_gc_interval_seconds = value;
    }
    if let Some(value) = patch.jwks_local_cache_max_entries {
        policy.jwks_local_cache_max_entries = value;
    }
    if let Some(value) = patch.jwks_http_timeout_seconds {
        policy.jwks_http_timeout_seconds = value;
    }
    if let Some(value) = patch.jwks_refresh_skew_seconds {
        policy.jwks_refresh_skew_seconds = value;
    }
    if let Some(value) = patch.jwks_shared_state_max_age_seconds {
        policy.jwks_shared_state_max_age_seconds = value;
    }
    if let Some(value) = patch.jwks_max_body_bytes {
        policy.jwks_max_body_bytes = value;
    }
    if let Some(value) = patch.jwks_http_retries {
        policy.jwks_http_retries = value;
    }
}
