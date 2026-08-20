use crate::management::types::PolicyDocument;

use super::super::{
    valid_access_token_ttl_secs, valid_auth_max_sessions, valid_auth_session_ttl_secs,
    valid_authorization_code_ttl_secs, valid_cleanup_interval_secs,
    valid_client_secret_expiration_days, valid_device_code_poll_interval_secs,
    valid_device_code_ttl_secs, valid_dpop_iat_window_secs, valid_dpop_nonce_ttl_secs,
    valid_jose_header_max_len, valid_jwt_introspection_exp_secs, valid_jwt_leeway_secs,
    valid_par_expires_in_secs, valid_recovery_token_ttl_secs, valid_refresh_token_ttl_secs,
    valid_request_object_jti_ttl_secs, valid_runtime_sync_interval_secs, valid_ssa_leeway_secs,
    valid_stepup_challenge_ttl_secs, valid_upstream_auth_ttl_secs,
    valid_upstream_logout_relay_ttl_secs, ConfigError,
};

type NumericPolicyValidator = fn(u64) -> bool;

#[derive(Clone, Copy)]
struct NumericPolicyField {
    key: &'static str,
    value: u64,
    expectation: &'static str,
    is_valid: NumericPolicyValidator,
}

pub(super) fn validate_numeric_policy_fields(policy: &PolicyDocument) -> Result<(), ConfigError> {
    numeric_policy_fields(policy)
        .into_iter()
        .try_for_each(validate_numeric_policy_field)?;
    validate_credential_lifecycle_order(policy)
}

fn validate_numeric_policy_field(field: NumericPolicyField) -> Result<(), ConfigError> {
    if (field.is_valid)(field.value) {
        return Ok(());
    }
    Err(ConfigError::InvalidNumberRange {
        key: field.key.to_string(),
        value: field.value.to_string(),
        expectation: field.expectation.to_string(),
    })
}

pub(super) fn validate_auth_max_sessions_policy(
    policy: &PolicyDocument,
) -> Result<(), ConfigError> {
    let auth_max_sessions =
        usize::try_from(policy.auth_max_sessions).map_err(|_| ConfigError::InvalidNumberRange {
            key: "auth_max_sessions".to_string(),
            value: policy.auth_max_sessions.to_string(),
            expectation: "a value in 1..=1000000 sessions".to_string(),
        })?;
    if !valid_auth_max_sessions(auth_max_sessions) {
        return Err(ConfigError::InvalidNumberRange {
            key: "auth_max_sessions".to_string(),
            value: policy.auth_max_sessions.to_string(),
            expectation: "a value in 1..=1000000 sessions".to_string(),
        });
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "existing declarative policy inventory; new oversized functions remain gated"
)]
fn numeric_policy_fields(policy: &PolicyDocument) -> Vec<NumericPolicyField> {
    vec![
        NumericPolicyField {
            key: "dpop_iat_window_seconds",
            value: u64::from(policy.dpop_iat_window_seconds),
            expectation: "a value in 1..=300 seconds",
            is_valid: valid_dpop_iat_window_secs,
        },
        NumericPolicyField {
            key: "dpop_nonce_ttl_seconds",
            value: u64::from(policy.dpop_nonce_ttl_seconds),
            expectation: "a value in 1..=3600 seconds",
            is_valid: valid_dpop_nonce_ttl_secs,
        },
        NumericPolicyField {
            key: "par_expires_in_seconds",
            value: u64::from(policy.par_expires_in_seconds),
            expectation: "a value in 1..=600 seconds",
            is_valid: valid_par_expires_in_secs,
        },
        NumericPolicyField {
            key: "device_code_ttl_seconds",
            value: u64::from(policy.device_code_ttl_seconds),
            expectation: "a value in 1..=3600 seconds",
            is_valid: valid_device_code_ttl_secs,
        },
        NumericPolicyField {
            key: "device_code_poll_interval_seconds",
            value: u64::from(policy.device_code_poll_interval_seconds),
            expectation: "a value in 5..=300 seconds",
            is_valid: valid_device_code_poll_interval_secs,
        },
        NumericPolicyField {
            key: "activation_token_default_ttl_seconds",
            value: u64::from(policy.activation_token_default_ttl_seconds),
            expectation: "a value in 300..=604800 seconds",
            is_valid: valid_recovery_token_ttl_secs,
        },
        NumericPolicyField {
            key: "password_reset_token_default_ttl_seconds",
            value: u64::from(policy.password_reset_token_default_ttl_seconds),
            expectation: "a value in 300..=604800 seconds",
            is_valid: valid_recovery_token_ttl_secs,
        },
        NumericPolicyField {
            key: "recovery_token_max_ttl_seconds",
            value: u64::from(policy.recovery_token_max_ttl_seconds),
            expectation: "a value in 300..=604800 seconds",
            is_valid: valid_recovery_token_ttl_secs,
        },
        NumericPolicyField {
            key: "client_secret_default_expiration_days",
            value: u64::from(policy.client_secret_default_expiration_days),
            expectation: "a value in 1..=365 days",
            is_valid: valid_client_secret_expiration_days,
        },
        NumericPolicyField {
            key: "client_secret_max_expiration_days",
            value: u64::from(policy.client_secret_max_expiration_days),
            expectation: "a value in 1..=365 days",
            is_valid: valid_client_secret_expiration_days,
        },
        NumericPolicyField {
            key: "jwt_leeway_seconds",
            value: u64::from(policy.jwt_leeway_seconds),
            expectation: "a value in 0..=300 seconds",
            is_valid: valid_jwt_leeway_secs,
        },
        NumericPolicyField {
            key: "ssa_leeway_seconds",
            value: u64::from(policy.ssa_leeway_seconds),
            expectation: "a value in 0..=300 seconds",
            is_valid: valid_ssa_leeway_secs,
        },
        NumericPolicyField {
            key: "jose_header_max_len",
            value: u64::from(policy.jose_header_max_len),
            expectation: "a value in 1..=65536 characters",
            is_valid: valid_jose_header_max_len,
        },
        NumericPolicyField {
            key: "access_token_time_to_live_seconds",
            value: u64::from(policy.access_token_time_to_live_seconds),
            expectation: "a value in 1..=86400 seconds",
            is_valid: valid_access_token_ttl_secs,
        },
        NumericPolicyField {
            key: "id_token_time_to_live_seconds",
            value: u64::from(policy.id_token_time_to_live_seconds),
            expectation: "a value in 1..=86400 seconds",
            is_valid: valid_access_token_ttl_secs,
        },
        NumericPolicyField {
            key: "refresh_token_time_to_live_seconds",
            value: u64::from(policy.refresh_token_time_to_live_seconds),
            expectation: "a value in 1..=7776000 seconds",
            is_valid: valid_refresh_token_ttl_secs,
        },
        NumericPolicyField {
            key: "authorization_code_time_to_live_seconds",
            value: u64::from(policy.authorization_code_time_to_live_seconds),
            expectation: "a value in 1..=600 seconds",
            is_valid: valid_authorization_code_ttl_secs,
        },
        NumericPolicyField {
            key: "auth_session_ttl_seconds",
            value: u64::from(policy.auth_session_ttl_seconds),
            expectation: "a value in 1..=86400 seconds",
            is_valid: valid_auth_session_ttl_secs,
        },
        NumericPolicyField {
            key: "request_object_jti_ttl_seconds",
            value: u64::from(policy.request_object_jti_ttl_seconds),
            expectation: "a value in 1..=3600 seconds",
            is_valid: valid_request_object_jti_ttl_secs,
        },
        NumericPolicyField {
            key: "stepup_challenge_ttl_seconds",
            value: u64::from(policy.stepup_challenge_ttl_seconds),
            expectation: "a value in 1..=600 seconds",
            is_valid: valid_stepup_challenge_ttl_secs,
        },
        NumericPolicyField {
            key: "jwt_introspection_exp_seconds",
            value: u64::from(policy.jwt_introspection_exp_seconds),
            expectation: "a value in 1..=60 seconds",
            is_valid: valid_jwt_introspection_exp_secs,
        },
        NumericPolicyField {
            key: "oidc_logout_session_ttl_seconds",
            value: u64::from(policy.oidc_logout_session_ttl_seconds),
            expectation: "a value in 1..=86400 seconds",
            is_valid: crate::oidc::session::valid_logout_session_ttl_secs,
        },
        NumericPolicyField {
            key: "oidc_backchannel_logout_timeout_seconds",
            value: u64::from(policy.oidc_backchannel_logout_timeout_seconds),
            expectation: "a value in 1..=60 seconds",
            is_valid: crate::oidc::config::valid_backchannel_logout_timeout_secs,
        },
        NumericPolicyField {
            key: "upstream_auth_ttl_seconds",
            value: u64::from(policy.upstream_auth_ttl_seconds),
            expectation: "a value in 1..=3600 seconds",
            is_valid: valid_upstream_auth_ttl_secs,
        },
        NumericPolicyField {
            key: "upstream_logout_relay_ttl_seconds",
            value: u64::from(policy.upstream_logout_relay_ttl_seconds),
            expectation: "a value in 1..=86400 seconds",
            is_valid: valid_upstream_logout_relay_ttl_secs,
        },
        NumericPolicyField {
            key: "upstream_discovery_cache_ttl_seconds",
            value: u64::from(policy.upstream_discovery_cache_ttl_seconds),
            expectation: "a value in 1..=86400 seconds",
            is_valid: valid_upstream_metadata_cache_ttl_secs_u64,
        },
        NumericPolicyField {
            key: "upstream_discovery_cache_max_entries",
            value: u64::from(policy.upstream_discovery_cache_max_entries),
            expectation: "a value in 1..=1000000 entries",
            is_valid: valid_upstream_metadata_cache_max_entries_u64,
        },
        NumericPolicyField {
            key: "upstream_jwks_cache_ttl_seconds",
            value: u64::from(policy.upstream_jwks_cache_ttl_seconds),
            expectation: "a value in 1..=86400 seconds",
            is_valid: valid_upstream_metadata_cache_ttl_secs_u64,
        },
        NumericPolicyField {
            key: "upstream_jwks_cache_max_entries",
            value: u64::from(policy.upstream_jwks_cache_max_entries),
            expectation: "a value in 1..=1000000 entries",
            is_valid: valid_upstream_metadata_cache_max_entries_u64,
        },
        NumericPolicyField {
            key: "cleanup_interval_seconds",
            value: u64::from(policy.cleanup_interval_seconds),
            expectation: "a value in 1..=3600 seconds",
            is_valid: valid_cleanup_interval_secs,
        },
        NumericPolicyField {
            key: "runtime_config_monitor_interval_seconds",
            value: u64::from(policy.runtime_config_monitor_interval_seconds),
            expectation: "a value in 1..=3600 seconds",
            is_valid: valid_runtime_sync_interval_secs,
        },
    ]
}

fn validate_credential_lifecycle_order(policy: &PolicyDocument) -> Result<(), ConfigError> {
    if policy.activation_token_default_ttl_seconds > policy.recovery_token_max_ttl_seconds {
        return Err(ConfigError::InvalidNumberRange {
            key: "activation_token_default_ttl_seconds".to_string(),
            value: policy.activation_token_default_ttl_seconds.to_string(),
            expectation: "a value no greater than recovery_token_max_ttl_seconds".to_string(),
        });
    }
    if policy.password_reset_token_default_ttl_seconds > policy.recovery_token_max_ttl_seconds {
        return Err(ConfigError::InvalidNumberRange {
            key: "password_reset_token_default_ttl_seconds".to_string(),
            value: policy.password_reset_token_default_ttl_seconds.to_string(),
            expectation: "a value no greater than recovery_token_max_ttl_seconds".to_string(),
        });
    }
    if policy.client_secret_default_expiration_days > policy.client_secret_max_expiration_days {
        return Err(ConfigError::InvalidNumberRange {
            key: "client_secret_default_expiration_days".to_string(),
            value: policy.client_secret_default_expiration_days.to_string(),
            expectation: "a value no greater than client_secret_max_expiration_days".to_string(),
        });
    }
    Ok(())
}

fn valid_upstream_metadata_cache_ttl_secs_u64(value: u64) -> bool {
    crate::upstream::valid_upstream_metadata_cache_ttl_secs(value)
}

fn valid_upstream_metadata_cache_max_entries_u64(value: u64) -> bool {
    u32::try_from(value).is_ok_and(crate::upstream::valid_upstream_metadata_cache_max_entries)
}
