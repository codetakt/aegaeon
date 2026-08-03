use crate::management::types::{PolicyDocument, PolicyPatchRequest};

pub(super) fn apply_base_policy_patch(policy: &mut PolicyDocument, patch: &PolicyPatchRequest) {
    if let Some(value) = patch.pkce_required {
        policy.pkce_required = value;
    }
    if let Some(value) = patch.dcr_enabled {
        policy.dcr_enabled = value;
    }
    if let Some(value) = patch.dcr_everparse_runtime_enabled {
        policy.dcr_everparse_runtime_enabled = value;
    }
    if let Some(value) = patch.require_state_parameter {
        policy.require_state_parameter = value;
    }
    if let Some(value) = patch.strict_authorize_redirect {
        policy.strict_authorize_redirect = value;
    }
    if let Some(value) = patch.require_client_auth_token {
        policy.require_client_auth_token = value;
    }
    if let Some(value) = patch.require_client_auth_par {
        policy.require_client_auth_par = value;
    }
    if let Some(value) = patch.require_client_auth_introspection {
        policy.require_client_auth_introspection = value;
    }
    if let Some(value) = patch.require_client_auth_revocation {
        policy.require_client_auth_revocation = value;
    }
    if let Some(value) = patch.sender_constraint {
        policy.sender_constraint = value;
    }
    if let Some(value) = patch.require_scope_subset {
        policy.require_scope_subset = value;
    }
    if let Some(value) = patch.require_audience_match {
        policy.require_audience_match = value;
    }
    if let Some(value) = patch.retain_refresh_chain {
        policy.retain_refresh_chain = value;
    }
    if let Some(value) = patch.enforce_refresh_sender_binding {
        policy.enforce_refresh_sender_binding = value;
    }
    if let Some(value) = patch.dpop_strict {
        policy.dpop_strict = value;
    }
    if let Some(value) = patch.dpop_iat_window_seconds {
        policy.dpop_iat_window_seconds = value;
    }
    if let Some(value) = patch.dpop_require_nonce {
        policy.dpop_require_nonce = value;
    }
    if let Some(value) = patch.dpop_nonce_ttl_seconds {
        policy.dpop_nonce_ttl_seconds = value;
    }
    if let Some(value) = patch.require_pushed_authorization_requests {
        policy.require_pushed_authorization_requests = value;
    }
    if let Some(value) = patch.par_expires_in_seconds {
        policy.par_expires_in_seconds = value;
    }
    if let Some(value) = patch.device_code_ttl_seconds {
        policy.device_code_ttl_seconds = value;
    }
    if let Some(value) = patch.device_code_poll_interval_seconds {
        policy.device_code_poll_interval_seconds = value;
    }
    if let Some(value) = patch.activation_token_default_ttl_seconds {
        policy.activation_token_default_ttl_seconds = value;
    }
    if let Some(value) = patch.password_reset_token_default_ttl_seconds {
        policy.password_reset_token_default_ttl_seconds = value;
    }
    if let Some(value) = patch.recovery_token_max_ttl_seconds {
        policy.recovery_token_max_ttl_seconds = value;
    }
    if let Some(value) = patch.client_secret_default_expiration_days {
        policy.client_secret_default_expiration_days = value;
    }
    if let Some(value) = patch.client_secret_max_expiration_days {
        policy.client_secret_max_expiration_days = value;
    }
    if let Some(value) = patch.private_key_jwt_enabled {
        policy.private_key_jwt_enabled = value;
    }
    if let Some(value) = patch.client_jwt_allowed_algs.as_ref() {
        policy.client_jwt_allowed_algs = normalized_unique_uppercase_values(value);
    }
    if let Some(value) = patch.client_jwt_require_kid {
        policy.client_jwt_require_kid = value;
    }
    if let Some(value) = patch.jwt_leeway_seconds {
        policy.jwt_leeway_seconds = value;
    }
    if let Some(value) = patch.pkjwt_jti_window_seconds {
        policy.pkjwt_jti_window_seconds = value;
    }
    if let Some(value) = patch.jose_header_max_len {
        policy.jose_header_max_len = value;
    }
}

fn normalized_unique_uppercase_values(values: &[String]) -> Vec<String> {
    values.iter().fold(Vec::new(), |mut normalized, value| {
        let candidate = value.trim().to_ascii_uppercase();
        if !candidate.is_empty() && !normalized.iter().any(|item| item == &candidate) {
            normalized.push(candidate);
        }
        normalized
    })
}
