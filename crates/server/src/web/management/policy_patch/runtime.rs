use crate::management::types::{PolicyDocument, PolicyPatchRequest};
use crate::runtime_keys::canonical_runtime_signing_algorithm_name;

pub(super) fn apply_runtime_policy_patch(policy: &mut PolicyDocument, patch: &PolicyPatchRequest) {
    if let Some(value) = patch.crypto_profile.as_deref() {
        policy.crypto_profile = value.trim().to_ascii_lowercase();
    }
    if let Some(value) = patch.allowed_signing_algorithms.as_ref() {
        policy.allowed_signing_algorithms = normalize_unique_signing_algorithm_policy_values(value);
    }
    if let Some(value) = patch.allowed_grant_types.as_ref() {
        policy.allowed_grant_types = value
            .iter()
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
            .collect();
    }

    if let Some(value) = patch.access_token_time_to_live_seconds {
        policy.access_token_time_to_live_seconds = value;
    }
    if let Some(value) = patch.id_token_time_to_live_seconds {
        policy.id_token_time_to_live_seconds = value;
    }
    if let Some(value) = patch.refresh_token_time_to_live_seconds {
        policy.refresh_token_time_to_live_seconds = value;
    }
    if let Some(value) = patch.authorization_code_time_to_live_seconds {
        policy.authorization_code_time_to_live_seconds = value;
    }
    if let Some(value) = patch.auth_session_ttl_seconds {
        policy.auth_session_ttl_seconds = value;
    }
    if let Some(value) = patch.auth_max_sessions {
        policy.auth_max_sessions = value;
    }
    if let Some(value) = patch.stepup_challenge_ttl_seconds {
        policy.stepup_challenge_ttl_seconds = value;
    }
    if let Some(value) = patch.upstream_auth_ttl_seconds {
        policy.upstream_auth_ttl_seconds = value;
    }
    if let Some(value) = patch.upstream_logout_relay_ttl_seconds {
        policy.upstream_logout_relay_ttl_seconds = value;
    }
    if let Some(value) = patch.upstream_discovery_cache_ttl_seconds {
        policy.upstream_discovery_cache_ttl_seconds = value;
    }
    if let Some(value) = patch.upstream_discovery_cache_max_entries {
        policy.upstream_discovery_cache_max_entries = value;
    }
    if let Some(value) = patch.upstream_jwks_cache_ttl_seconds {
        policy.upstream_jwks_cache_ttl_seconds = value;
    }
    if let Some(value) = patch.upstream_jwks_cache_max_entries {
        policy.upstream_jwks_cache_max_entries = value;
    }
    if let Some(value) = patch.cleanup_interval_seconds {
        policy.cleanup_interval_seconds = value;
    }
    if let Some(value) = patch.runtime_config_monitor_interval_seconds {
        policy.runtime_config_monitor_interval_seconds = value;
    }
}

fn normalize_signing_algorithm_policy_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(
            canonical_runtime_signing_algorithm_name(trimmed)
                .map_or_else(|| trimmed.to_ascii_uppercase(), str::to_string),
        )
    }
}

fn normalize_unique_signing_algorithm_policy_values(values: &[String]) -> Vec<String> {
    values.iter().fold(Vec::new(), |mut normalized, value| {
        if let Some(candidate) = normalize_signing_algorithm_policy_value(value) {
            if !normalized.iter().any(|item| item == &candidate) {
                normalized.push(candidate);
            }
        }
        normalized
    })
}
