use axum::response::Response;

use crate::config::{
    valid_auth_max_sessions, valid_auth_session_ttl_secs, valid_cleanup_interval_secs,
    valid_client_secret_expiration_days, valid_device_code_poll_interval_secs,
    valid_device_code_ttl_secs, valid_jose_header_max_len, valid_jwt_leeway_secs,
    valid_par_expires_in_secs, valid_recovery_token_ttl_secs, valid_runtime_sync_interval_secs,
    valid_ssa_leeway_secs,
};
use crate::management::types::PolicyDocument;

use super::invalid_request;

pub(in crate::web::management::configuration_documents::policy_validation) fn validate_session_and_protocol_ranges(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    if !valid_auth_session_ttl_secs(u64::from(policy.auth_session_ttl_seconds)) {
        return Err(invalid_request(
            "Auth session TTL exceeds the supported policy range",
            request_id,
        ));
    }
    let auth_max_sessions = usize::try_from(policy.auth_max_sessions)
        .ok()
        .filter(|value| valid_auth_max_sessions(*value));
    if auth_max_sessions.is_none() {
        return Err(invalid_request(
            "Auth session capacity exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_par_expires_in_secs(u64::from(policy.par_expires_in_seconds)) {
        return Err(invalid_request(
            "PAR request_uri TTL exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_device_code_ttl_secs(u64::from(policy.device_code_ttl_seconds)) {
        return Err(invalid_request(
            "Device code TTL exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_device_code_poll_interval_secs(u64::from(policy.device_code_poll_interval_seconds)) {
        return Err(invalid_request(
            "Device code poll interval exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_recovery_token_lifecycle(policy) {
        return Err(invalid_request(
            "Recovery token lifecycle exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_client_secret_lifecycle(policy) {
        return Err(invalid_request(
            "Client secret lifecycle exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_jwt_leeway_secs(u64::from(policy.jwt_leeway_seconds)) {
        return Err(invalid_request(
            "JWT leeway exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_ssa_leeway_secs(u64::from(policy.ssa_leeway_seconds)) {
        return Err(invalid_request(
            "SSA leeway exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_jose_header_max_len(u64::from(policy.jose_header_max_len)) {
        return Err(invalid_request(
            "JOSE protected header length exceeds the supported policy range",
            request_id,
        ));
    }
    if !valid_cleanup_interval_secs(u64::from(policy.cleanup_interval_seconds))
        || !valid_runtime_sync_interval_secs(u64::from(
            policy.runtime_config_monitor_interval_seconds,
        ))
    {
        return Err(invalid_request(
            "Runtime maintenance intervals exceed the supported policy range",
            request_id,
        ));
    }

    Ok(())
}

fn valid_recovery_token_lifecycle(policy: &PolicyDocument) -> bool {
    let activation_default = u64::from(policy.activation_token_default_ttl_seconds);
    let password_reset_default = u64::from(policy.password_reset_token_default_ttl_seconds);
    let max = u64::from(policy.recovery_token_max_ttl_seconds);
    valid_recovery_token_ttl_secs(activation_default)
        && valid_recovery_token_ttl_secs(password_reset_default)
        && valid_recovery_token_ttl_secs(max)
        && activation_default <= max
        && password_reset_default <= max
}

fn valid_client_secret_lifecycle(policy: &PolicyDocument) -> bool {
    let default_days = u64::from(policy.client_secret_default_expiration_days);
    let max_days = u64::from(policy.client_secret_max_expiration_days);
    valid_client_secret_expiration_days(default_days)
        && valid_client_secret_expiration_days(max_days)
        && default_days <= max_days
}
