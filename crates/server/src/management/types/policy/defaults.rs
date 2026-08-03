pub(super) const fn default_jwt_bearer_jti_window_seconds() -> u32 {
    300
}

pub(super) const fn default_auth_session_ttl_seconds() -> u32 {
    8 * 3600
}

pub(super) const fn default_auth_max_sessions() -> u32 {
    10_000
}

pub(super) const fn default_stepup_challenge_ttl_seconds() -> u32 {
    300
}

pub(super) const fn default_jwt_introspection_exp_seconds() -> u32 {
    60
}

pub(super) const fn default_upstream_auth_ttl_seconds() -> u32 {
    300
}

pub(super) const fn default_upstream_logout_relay_ttl_seconds() -> u32 {
    300
}

pub(super) const fn default_device_code_ttl_seconds() -> u32 {
    crate::config::DEFAULT_DEVICE_CODE_TTL_SECS as u32
}

pub(super) const fn default_device_code_poll_interval_seconds() -> u32 {
    crate::config::DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS as u32
}

pub(super) const fn default_activation_token_ttl_seconds() -> u32 {
    crate::config::DEFAULT_ACTIVATION_TOKEN_TTL_SECS as u32
}

pub(super) const fn default_password_reset_token_ttl_seconds() -> u32 {
    crate::config::DEFAULT_PASSWORD_RESET_TOKEN_TTL_SECS as u32
}

pub(super) const fn default_recovery_token_max_ttl_seconds() -> u32 {
    crate::config::MAX_RECOVERY_TOKEN_TTL_SECS as u32
}

pub(super) const fn default_client_secret_expiration_days() -> u32 {
    crate::config::DEFAULT_CLIENT_SECRET_EXPIRATION_DAYS as u32
}

pub(super) const fn default_client_secret_max_expiration_days() -> u32 {
    crate::config::MAX_CLIENT_SECRET_EXPIRATION_DAYS as u32
}

pub(super) const fn default_upstream_metadata_cache_ttl_seconds() -> u32 {
    300
}

pub(super) const fn default_upstream_metadata_cache_max_entries() -> u32 {
    crate::upstream::DEFAULT_UPSTREAM_METADATA_CACHE_MAX_ENTRIES as u32
}

pub(super) const fn default_runtime_sync_interval_seconds() -> u32 {
    30
}

pub(super) const fn default_cleanup_interval_seconds() -> u32 {
    60
}

pub(super) const fn default_jwks_circuit_open_fails() -> u32 {
    3
}

pub(super) const fn default_jwks_circuit_reset_seconds() -> u32 {
    30
}

pub(super) const fn default_jwks_cache_ttl_seconds() -> u32 {
    300
}

pub(super) const fn default_jwks_cache_gc_interval_seconds() -> u32 {
    600
}

pub(super) const fn default_jwks_http_timeout_seconds() -> u32 {
    5
}

pub(super) const fn default_jwks_refresh_skew_seconds() -> u32 {
    10
}

pub(super) const fn default_jwks_shared_state_max_age_seconds() -> u32 {
    86_400
}

pub(super) const fn default_jwks_max_body_bytes() -> u32 {
    64 * 1024
}

pub(super) const fn default_jwks_local_cache_max_entries() -> u32 {
    crate::client_registry::DEFAULT_JWKS_LOCAL_CACHE_MAX_ENTRIES as u32
}

pub(super) const fn default_jwks_http_retries() -> u32 {
    2
}

pub(super) const fn default_federation_entity_cache_ttl_seconds() -> u32 {
    1_800
}

pub(super) const fn default_federation_trust_chain_cache_ttl_seconds() -> u32 {
    3_600
}

pub(super) const fn default_federation_cache_max_entries() -> u32 {
    1_000
}

pub(super) fn default_crypto_profile() -> String {
    "verified".to_string()
}
