use super::keys::rsa_public_jwk_from_private_der;
use super::*;
use crate::management::types::PolicySenderConstraint;
use crate::runtime_keys::{
    RuntimeKey, RuntimeKeyAlgorithm, RuntimeKeyProvider, RuntimeKeySet, RuntimeKeyUsage,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::error::Error as StdError;
use std::io;
use std::sync::MutexGuard;

mod env_inventory;
mod issuer;
mod jwks;
#[cfg(feature = "kms-aws")]
mod kms_parity;
mod management_snapshot;

type TestResult = std::result::Result<(), Box<dyn StdError>>;

const TEST_RSA_PRIVATE_KEY_PEM: &str =
    include_str!("../../../tests/fixtures/rsa2048-private.pk8.pem");

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn new(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var_os(key);
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(ref value) = self.previous {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn env_lock() -> std::result::Result<MutexGuard<'static, ()>, io::Error> {
    crate::util::SERVER_TEST_ENV_GUARD
        .lock()
        .map_err(|err| io::Error::other(err.to_string()))
}

fn managed_oidc_runtime_key_environment_id() -> uuid::Uuid {
    uuid::Uuid::from_u128(0x3333_4444_5555_6666_7777_8888_9999_aaaa)
}

fn managed_oidc_key_handle_context(
    provider: RuntimeKeyProvider,
    kid: &str,
) -> crate::key_encryption::KeyHandleEncryptionContext<'_> {
    crate::key_encryption::KeyHandleEncryptionContext::new(
        managed_oidc_runtime_key_environment_id(),
        RuntimeKeyUsage::OidcIdTokenSigning.as_db_str(),
        provider.as_db_str(),
        RuntimeKeyAlgorithm::Rs256.as_str(),
        kid,
    )
}

fn encrypt_managed_oidc_key_handle(
    plaintext_handle: &str,
    kek: &[u8; 32],
    provider: RuntimeKeyProvider,
    kid: &str,
) -> std::result::Result<String, crate::key_encryption::KeyHandleEncryptionError> {
    crate::key_encryption::encrypt_key_handle(
        plaintext_handle,
        kek,
        managed_oidc_key_handle_context(provider, kid),
    )
}

fn oidc_policy(enabled: bool) -> PolicyDocument {
    PolicyDocument {
        pkce_required: true,
        dcr_enabled: false,
        dcr_everparse_runtime_enabled: false,
        require_state_parameter: true,
        strict_authorize_redirect: true,
        require_client_auth_token: true,
        require_client_auth_par: true,
        require_client_auth_introspection: true,
        require_client_auth_revocation: true,
        sender_constraint: PolicySenderConstraint::Dpop,
        require_scope_subset: true,
        require_audience_match: true,
        retain_refresh_chain: true,
        enforce_refresh_sender_binding: true,
        dpop_strict: true,
        dpop_iat_window_seconds: 300,
        dpop_require_nonce: true,
        dpop_nonce_ttl_seconds: 300,
        require_pushed_authorization_requests: false,
        par_expires_in_seconds: 90,
        device_code_ttl_seconds: crate::config::DEFAULT_DEVICE_CODE_TTL_SECS as u32,
        device_code_poll_interval_seconds: crate::config::DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS
            as u32,
        activation_token_default_ttl_seconds: crate::config::DEFAULT_ACTIVATION_TOKEN_TTL_SECS
            as u32,
        password_reset_token_default_ttl_seconds:
            crate::config::DEFAULT_PASSWORD_RESET_TOKEN_TTL_SECS as u32,
        recovery_token_max_ttl_seconds: crate::config::MAX_RECOVERY_TOKEN_TTL_SECS as u32,
        client_secret_default_expiration_days: crate::config::DEFAULT_CLIENT_SECRET_EXPIRATION_DAYS
            as u32,
        client_secret_max_expiration_days: crate::config::MAX_CLIENT_SECRET_EXPIRATION_DAYS as u32,
        private_key_jwt_enabled: false,
        client_jwt_allowed_algs: vec!["RS256".to_string()],
        client_jwt_require_kid: false,
        jwt_leeway_seconds: 60,
        pkjwt_jti_window_seconds: 300,
        jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN as u32,
        jwks_allow_kid_reuse: false,
        jwks_circuit_open_fails: 3,
        jwks_circuit_reset_seconds: 30,
        jwks_cache_ttl_seconds: 300,
        jwks_cache_gc_interval_seconds: 600,
        jwks_local_cache_max_entries: 4096,
        jwks_http_timeout_seconds: 5,
        jwks_refresh_skew_seconds: 10,
        jwks_shared_state_max_age_seconds: 86_400,
        jwks_max_body_bytes: 64 * 1024,
        jwks_http_retries: 2,
        jwt_bearer_allow_client_subject: false,
        jwt_bearer_jti_window_seconds: 300,
        request_object_jti_ttl_seconds: 600,
        request_object_everparse_runtime_enabled: false,
        jwt_access_tokens_enabled: false,
        jwt_introspection_enabled: false,
        jwt_introspection_exp_seconds: 60,
        authorization_details_types_supported: Vec::new(),
        acr_values_supported: Vec::new(),
        default_acr: None,
        local_password_acr: None,
        dcr_require_pkce_for_public: false,
        dcr_require_pkce_for_confidential: false,
        dcr_require_sender_constrained: false,
        dcr_allowed_sender_methods: vec!["dpop".to_string()],
        ssa_jwt_pem: None,
        ssa_expected_iss: None,
        ssa_expected_aud: None,
        ssa_leeway_seconds: 120,
        oidc_enabled: enabled,
        oidc_enable_discovery: true,
        oidc_enable_userinfo: true,
        oidc_enable_logout: false,
        oidc_enable_backchannel_logout: false,
        oidc_logout_session_ttl_seconds: 600,
        oidc_backchannel_logout_timeout_seconds: 2,
        oidc_require_nonce: false,
        mtls_enabled: false,
        mtls_base_url: None,
        mtls_alias_par_enabled: false,
        federation_outbound_allowed_domains: Vec::new(),
        upstream_outbound_allowed_domains: Vec::new(),
        federation_entity_cache_ttl_seconds: 1_800,
        federation_trust_chain_cache_ttl_seconds: 3_600,
        federation_cache_max_entries: 1_000,
        crypto_profile: "verified".to_string(),
        allowed_signing_algorithms: vec!["RS256".to_string()],
        allowed_grant_types: vec!["authorization_code".to_string()],
        access_token_time_to_live_seconds: 3600,
        id_token_time_to_live_seconds: 3600,
        refresh_token_time_to_live_seconds: 86400,
        authorization_code_time_to_live_seconds: 300,
        auth_session_ttl_seconds: 28800,
        auth_max_sessions: 10000,
        stepup_challenge_ttl_seconds: 300,
        upstream_auth_ttl_seconds: 300,
        upstream_logout_relay_ttl_seconds: 300,
        upstream_discovery_cache_ttl_seconds: 300,
        upstream_discovery_cache_max_entries: 4096,
        upstream_jwks_cache_ttl_seconds: 300,
        upstream_jwks_cache_max_entries: 4096,
        cleanup_interval_seconds: 60,
        runtime_config_monitor_interval_seconds: 30,
    }
}

fn managed_oidc_signing_runtime_key(
    kid: &str,
    encrypted_key_handle: String,
) -> std::result::Result<RuntimeKey, OidcConfigError> {
    let parsed = pem::parse(TEST_RSA_PRIVATE_KEY_PEM)?;
    Ok(RuntimeKey {
        environment_id: managed_oidc_runtime_key_environment_id(),
        usage: RuntimeKeyUsage::OidcIdTokenSigning,
        algorithm: RuntimeKeyAlgorithm::Rs256,
        provider: RuntimeKeyProvider::DatabaseEncrypted,
        status: crate::runtime_keys::RuntimeKeyStatus::Active,
        retiring_expires_at_epoch_secs: None,
        kid: kid.to_string(),
        public_jwk: rsa_public_jwk_from_private_der(kid, parsed.contents())?,
        key_handle: encrypted_key_handle,
        provider_configuration: serde_json::json!({}),
    })
}

fn require_err<T, E>(
    result: std::result::Result<T, E>,
    message: &str,
) -> std::result::Result<E, io::Error> {
    match result {
        Ok(_) => Err(io::Error::other(message)),
        Err(err) => Ok(err),
    }
}
