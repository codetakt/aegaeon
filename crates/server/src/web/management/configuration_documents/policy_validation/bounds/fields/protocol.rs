use crate::management::types::PolicyDocument;

use super::NumericPolicyField;

pub(super) fn protocol_and_replay_fields(policy: &PolicyDocument) -> [NumericPolicyField; 16] {
    [
        ("dpop_iat_window_seconds", policy.dpop_iat_window_seconds),
        ("dpop_nonce_ttl_seconds", policy.dpop_nonce_ttl_seconds),
        ("par_expires_in_seconds", policy.par_expires_in_seconds),
        ("device_code_ttl_seconds", policy.device_code_ttl_seconds),
        (
            "device_code_poll_interval_seconds",
            policy.device_code_poll_interval_seconds,
        ),
        (
            "activation_token_default_ttl_seconds",
            policy.activation_token_default_ttl_seconds,
        ),
        (
            "password_reset_token_default_ttl_seconds",
            policy.password_reset_token_default_ttl_seconds,
        ),
        (
            "recovery_token_max_ttl_seconds",
            policy.recovery_token_max_ttl_seconds,
        ),
        (
            "client_secret_default_expiration_days",
            policy.client_secret_default_expiration_days,
        ),
        (
            "client_secret_max_expiration_days",
            policy.client_secret_max_expiration_days,
        ),
        ("jwt_leeway_seconds", policy.jwt_leeway_seconds),
        ("pkjwt_jti_window_seconds", policy.pkjwt_jti_window_seconds),
        (
            "jwt_bearer_jti_window_seconds",
            policy.jwt_bearer_jti_window_seconds,
        ),
        (
            "request_object_jti_ttl_seconds",
            policy.request_object_jti_ttl_seconds,
        ),
        ("jose_header_max_len", policy.jose_header_max_len),
        ("ssa_leeway_seconds", policy.ssa_leeway_seconds),
    ]
}
