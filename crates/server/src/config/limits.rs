pub const MAX_ACCESS_TOKEN_TTL_SECS: u64 = 86_400;
pub const MAX_REFRESH_TOKEN_TTL_SECS: u64 = 90 * 24 * 60 * 60;
pub const MAX_AUTHORIZATION_CODE_TTL_SECS: u64 = 600;
pub const DEFAULT_AUTHORIZATION_CODE_TTL_SECS: u64 = 300;
pub const MAX_PAR_EXPIRES_IN_SECS: u64 = 600;
pub const DEFAULT_PAR_EXPIRES_IN_SECS: u64 = 90;
pub const DEFAULT_DEVICE_CODE_TTL_SECS: u64 = 600;
pub const MAX_DEVICE_CODE_TTL_SECS: u64 = 3_600;
pub const DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS: u64 = 5;
pub const MAX_DEVICE_CODE_POLL_INTERVAL_SECS: u64 = 300;
pub const DEFAULT_ACTIVATION_TOKEN_TTL_SECS: u64 = 24 * 60 * 60;
pub const DEFAULT_PASSWORD_RESET_TOKEN_TTL_SECS: u64 = 60 * 60;
pub const MIN_RECOVERY_TOKEN_TTL_SECS: u64 = 5 * 60;
pub const MAX_RECOVERY_TOKEN_TTL_SECS: u64 = 7 * 24 * 60 * 60;
pub const DEFAULT_CLIENT_SECRET_EXPIRATION_DAYS: u64 = 90;
pub const MAX_CLIENT_SECRET_EXPIRATION_DAYS: u64 = 365;
pub const DEFAULT_CLIENT_ASSERTION_REPLAY_WINDOW_SECS: i64 = 300;
pub const DEFAULT_REQUEST_OBJECT_JTI_TTL_SECS: u64 = 600;
pub const MAX_REQUEST_OBJECT_JTI_TTL_SECS: u64 = 3_600;
pub const MAX_JWT_LEEWAY_SECS: u64 = 300;
pub const MAX_DPOP_IAT_WINDOW_SECS: u64 = 300;
pub const MAX_DPOP_NONCE_TTL_SECS: u64 = 3_600;
pub const MAX_SSA_LEEWAY_SECS: u64 = MAX_JWT_LEEWAY_SECS;
pub const MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS: i64 = 3_600;
pub const DEFAULT_AUTH_SESSION_TTL_SECS: u64 = 8 * 3_600;
pub const MAX_AUTH_SESSION_TTL_SECS: u64 = 24 * 3_600;
pub const DEFAULT_AUTH_MAX_SESSIONS: usize = 10_000;
pub const MAX_AUTH_MAX_SESSIONS: usize = 1_000_000;
pub const DEFAULT_STEPUP_CHALLENGE_TTL_SECS: u64 = 300;
pub const MAX_STEPUP_CHALLENGE_TTL_SECS: u64 = 600;
pub const DEFAULT_JWT_INTROSPECTION_EXP_SECS: u64 = 60;
pub const MAX_JWT_INTROSPECTION_EXP_SECS: u64 = 60;
pub const DEFAULT_UPSTREAM_AUTH_TTL_SECS: u64 = 300;
pub const MAX_UPSTREAM_AUTH_TTL_SECS: u64 = 3_600;
pub const DEFAULT_UPSTREAM_LOGOUT_RELAY_TTL_SECS: u64 = 300;
pub const MAX_UPSTREAM_LOGOUT_RELAY_TTL_SECS: u64 = 86_400;
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 60;
pub const MAX_CLEANUP_INTERVAL_SECS: u64 = 3_600;
pub const DEFAULT_RUNTIME_SYNC_INTERVAL_SECS: u64 = 30;
pub const MAX_RUNTIME_SYNC_INTERVAL_SECS: u64 = 3_600;
pub const MAX_JOSE_HEADER_LEN: u64 = 65_536;

#[must_use]
pub const fn valid_access_token_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_ACCESS_TOKEN_TTL_SECS
}

#[must_use]
pub const fn valid_refresh_token_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_REFRESH_TOKEN_TTL_SECS
}

#[must_use]
pub const fn valid_authorization_code_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_AUTHORIZATION_CODE_TTL_SECS
}

#[must_use]
pub const fn valid_par_expires_in_secs(value: u64) -> bool {
    value > 0 && value <= MAX_PAR_EXPIRES_IN_SECS
}

#[must_use]
pub const fn valid_device_code_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_DEVICE_CODE_TTL_SECS
}

#[must_use]
pub const fn valid_device_code_poll_interval_secs(value: u64) -> bool {
    value >= DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS && value <= MAX_DEVICE_CODE_POLL_INTERVAL_SECS
}

#[must_use]
pub const fn valid_recovery_token_ttl_secs(value: u64) -> bool {
    value >= MIN_RECOVERY_TOKEN_TTL_SECS && value <= MAX_RECOVERY_TOKEN_TTL_SECS
}

#[must_use]
pub const fn valid_client_secret_expiration_days(value: u64) -> bool {
    value > 0 && value <= MAX_CLIENT_SECRET_EXPIRATION_DAYS
}

#[must_use]
pub const fn valid_request_object_jti_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_REQUEST_OBJECT_JTI_TTL_SECS
}

#[must_use]
pub const fn valid_jwt_leeway_secs(value: u64) -> bool {
    value <= MAX_JWT_LEEWAY_SECS
}

#[must_use]
pub const fn valid_dpop_iat_window_secs(value: u64) -> bool {
    value > 0 && value <= MAX_DPOP_IAT_WINDOW_SECS
}

#[must_use]
pub const fn valid_dpop_nonce_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_DPOP_NONCE_TTL_SECS
}

#[must_use]
pub const fn valid_auth_session_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_AUTH_SESSION_TTL_SECS
}

#[must_use]
pub const fn valid_auth_max_sessions(value: usize) -> bool {
    value > 0 && value <= MAX_AUTH_MAX_SESSIONS
}

#[must_use]
pub const fn valid_stepup_challenge_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_STEPUP_CHALLENGE_TTL_SECS
}

#[must_use]
pub const fn valid_jwt_introspection_exp_secs(value: u64) -> bool {
    value > 0 && value <= MAX_JWT_INTROSPECTION_EXP_SECS
}

#[must_use]
pub const fn valid_upstream_auth_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_UPSTREAM_AUTH_TTL_SECS
}

#[must_use]
pub const fn valid_upstream_logout_relay_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_UPSTREAM_LOGOUT_RELAY_TTL_SECS
}

#[must_use]
pub const fn valid_runtime_sync_interval_secs(value: u64) -> bool {
    value > 0 && value <= MAX_RUNTIME_SYNC_INTERVAL_SECS
}

#[must_use]
pub const fn valid_jose_header_max_len(value: u64) -> bool {
    value > 0 && value <= MAX_JOSE_HEADER_LEN
}

#[must_use]
pub const fn valid_cleanup_interval_secs(value: u64) -> bool {
    value > 0 && value <= MAX_CLEANUP_INTERVAL_SECS
}

#[must_use]
pub const fn valid_ssa_leeway_secs(value: u64) -> bool {
    value <= MAX_SSA_LEEWAY_SECS
}

#[must_use]
pub const fn valid_client_assertion_replay_window_secs(value: i64) -> bool {
    value > 0 && value <= MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS
}
