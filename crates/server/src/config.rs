mod atomic_store_topology;
mod database;
mod env_vars;
mod environment;
mod federation;
mod limits;
mod management_policy;
mod oidc_boundary;
mod removed_env;
mod runtime_boundary;
mod runtime_views;
mod startup_policy_boundary;
mod transport;

use self::atomic_store_topology::validate_authorization_code_grant_commit_store_topology;
pub use self::database::DatabaseConfig;
pub use self::database::PostgresDatabaseUrl;
pub(crate) use self::env_vars::try_required_env_flag;
pub use self::env_vars::{
    env_flag, env_num, env_num_with, try_env_csv_list, try_env_flag, try_env_num, try_env_num_with,
    try_env_optional_string, validate_public_base_url_value,
};
pub use self::federation::UpstreamRuntimeConfig;
pub use self::limits::{
    valid_access_token_ttl_secs, valid_auth_max_sessions, valid_auth_session_ttl_secs,
    valid_authorization_code_ttl_secs, valid_cleanup_interval_secs,
    valid_client_assertion_replay_window_secs, valid_client_secret_expiration_days,
    valid_device_code_poll_interval_secs, valid_device_code_ttl_secs, valid_dpop_iat_window_secs,
    valid_dpop_nonce_ttl_secs, valid_jose_header_max_len, valid_jwt_introspection_exp_secs,
    valid_jwt_leeway_secs, valid_par_expires_in_secs, valid_recovery_token_ttl_secs,
    valid_refresh_token_ttl_secs, valid_request_object_jti_ttl_secs,
    valid_runtime_sync_interval_secs, valid_ssa_leeway_secs, valid_stepup_challenge_ttl_secs,
    valid_upstream_auth_ttl_secs, valid_upstream_logout_relay_ttl_secs,
    DEFAULT_ACTIVATION_TOKEN_TTL_SECS, DEFAULT_AUTHORIZATION_CODE_TTL_SECS,
    DEFAULT_AUTH_MAX_SESSIONS, DEFAULT_AUTH_SESSION_TTL_SECS, DEFAULT_CLEANUP_INTERVAL_SECS,
    DEFAULT_CLIENT_ASSERTION_REPLAY_WINDOW_SECS, DEFAULT_CLIENT_SECRET_EXPIRATION_DAYS,
    DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS, DEFAULT_DEVICE_CODE_TTL_SECS,
    DEFAULT_JWT_INTROSPECTION_EXP_SECS, DEFAULT_PAR_EXPIRES_IN_SECS,
    DEFAULT_PASSWORD_RESET_TOKEN_TTL_SECS, DEFAULT_REQUEST_OBJECT_JTI_TTL_SECS,
    DEFAULT_RUNTIME_SYNC_INTERVAL_SECS, DEFAULT_STEPUP_CHALLENGE_TTL_SECS,
    DEFAULT_UPSTREAM_AUTH_TTL_SECS, DEFAULT_UPSTREAM_LOGOUT_RELAY_TTL_SECS,
    MAX_ACCESS_TOKEN_TTL_SECS, MAX_AUTHORIZATION_CODE_TTL_SECS, MAX_AUTH_MAX_SESSIONS,
    MAX_AUTH_SESSION_TTL_SECS, MAX_CLEANUP_INTERVAL_SECS, MAX_CLIENT_ASSERTION_REPLAY_WINDOW_SECS,
    MAX_CLIENT_SECRET_EXPIRATION_DAYS, MAX_DEVICE_CODE_POLL_INTERVAL_SECS,
    MAX_DEVICE_CODE_TTL_SECS, MAX_DPOP_IAT_WINDOW_SECS, MAX_DPOP_NONCE_TTL_SECS,
    MAX_JOSE_HEADER_LEN, MAX_JWT_INTROSPECTION_EXP_SECS, MAX_JWT_LEEWAY_SECS,
    MAX_PAR_EXPIRES_IN_SECS, MAX_RECOVERY_TOKEN_TTL_SECS, MAX_REFRESH_TOKEN_TTL_SECS,
    MAX_REQUEST_OBJECT_JTI_TTL_SECS, MAX_RUNTIME_SYNC_INTERVAL_SECS, MAX_SSA_LEEWAY_SECS,
    MAX_STEPUP_CHALLENGE_TTL_SECS, MAX_UPSTREAM_AUTH_TTL_SECS, MAX_UPSTREAM_LOGOUT_RELAY_TTL_SECS,
    MIN_RECOVERY_TOKEN_TTL_SECS,
};
use self::oidc_boundary::{
    configured_oidc_startup_key_material_env_keys, configured_oidc_startup_policy_env_keys,
};
use self::removed_env::reject_removed_database_runtime_envs;
pub(crate) use self::runtime_boundary::redis_store_urls_reference_same_endpoint;
pub use self::runtime_boundary::{
    require_shared_runtime_store_url, test_runtime_helpers_allowed_by_build, RedisStoreUrl,
    RuntimeRedisAtomicGroup, RuntimeStateBoundaryConfig, RuntimeStateNamespace,
    SharedRuntimeStoreUrl,
};
pub use self::runtime_views::{GrantRuntimeConfig, JwtRuntimeConfig, TokenRuntimeConfig};
use self::startup_policy_boundary::configured_startup_managed_policy_env_keys;
pub use self::transport::TransportSecurityConfig;
pub(crate) use management_policy::validate_management_policy_for_runtime;
#[cfg(test)]
use std::env;
use thiserror::Error;

#[cfg(test)]
use crate::policy::SenderConstraint;
use crate::policy::{default_grant_types, SecurityPolicy};
use aegaeon_jose::algorithms::CryptoProfile;
use aegaeon_jose::policy::{self as jose_policy};

const DEPLOYMENT_MODE_ENV: &str = "AEGAEON_DEPLOYMENT_MODE";
const REMOVED_UNSHARED_RUNTIME_STATE_ENV: &str = "AEGAEON_ALLOW_UNSHARED_RUNTIME_STATE";
const REMOVED_EPHEMERAL_RUNTIME_STATE_ENV: &str = "AEGAEON_ALLOW_EPHEMERAL_RUNTIME_STATE";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{key} must be valid Unicode")]
    NonUnicode { key: String },

    #[error(
        "{key} must be a boolean: expected 1/0, true/false, yes/no, or on/off (got {value:?})"
    )]
    InvalidBoolean { key: String, value: String },

    #[error("{key} has invalid numeric value {value:?}: {reason}")]
    InvalidNumber {
        key: String,
        value: String,
        reason: String,
    },

    #[error("{key} has invalid numeric value {value}: expected {expectation}")]
    InvalidNumberRange {
        key: String,
        value: String,
        expectation: String,
    },

    #[error("{key} has invalid value {value:?}: {reason}")]
    InvalidValue {
        key: String,
        value: String,
        reason: String,
    },

    #[error("configured ACR {configured:?} is not listed in the supported ACR values")]
    InvalidAcr { configured: String },

    #[error("{key} contains invalid IP/CIDR entry {entry:?}")]
    InvalidIpNet { key: String, entry: String },

    #[error("management policy cryptoProfile must be verified (got {value:?})")]
    InvalidCryptoProfile { value: String },
}

#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    database: DatabaseConfig,
    transport: TransportSecurityConfig,
    security_policy: SecurityPolicy,
    runtime_state_boundary: RuntimeStateBoundaryConfig,
}

impl BootstrapConfig {
    #[must_use]
    pub fn database(&self) -> &DatabaseConfig {
        &self.database
    }

    pub fn into_runtime_baseline(self) -> ServerConfig {
        let mut cfg =
            ServerConfig::baseline_with_database(self.runtime_state_boundary, self.database);
        cfg.transport = self.transport;
        cfg.security_policy = self.security_policy;
        cfg.transport.apply_security_policy(&cfg.security_policy);
        cfg
    }
}

#[derive(Clone, Debug)]
// Environment-driven server posture is modeled as explicit toggles.
#[allow(clippy::struct_excessive_bools)]
pub struct ServerConfig {
    // Authorization behavior
    pub strict_authorize_redirect: bool, // 302 redirect vs JSON
    pub require_state: bool,             // Require 'state' on /authorize
    pub require_pushed_authorization_requests: bool,

    // Client authentication requirements
    pub require_client_auth_introspection: bool,
    pub require_client_auth_revocation: bool,
    pub require_client_auth_par: bool,
    pub require_client_auth_token: bool,

    // DPoP verification
    pub dpop_strict: bool,
    pub dpop_iat_window_secs: u64,
    pub require_dpop_nonce: bool,
    pub dpop_nonce_ttl_secs: u64,
    pub enable_private_key_jwt: bool,
    /// RFC 7523 JWT Bearer authorization grant (urn:ietf:params:oauth:grant-type:jwt-bearer).
    pub enable_jwt_bearer_grant: bool,
    /// Allow `sub == client_id` in JWT Bearer assertions (RFC 7523) when explicitly enabled.
    ///
    /// Default is `false` to keep JWT kinds mutually exclusive (JWT BCP / RFC 8725).
    pub allow_jwt_bearer_client_subject: bool,
    /// RFC 8693 OAuth 2.0 Token Exchange (urn:ietf:params:oauth:grant-type:token-exchange).
    pub enable_token_exchange: bool,
    /// RFC 8628 OAuth 2.0 Device Authorization Grant (opt-in).
    pub enable_device_authz: bool,
    /// Management-policy grant allowlist projected into runtime metadata and admission checks.
    pub allowed_grant_types: Vec<String>,
    /// RFC 9068 JWT Access Tokens (opt-in).
    pub enable_jwt_access_tokens: bool,
    /// RFC 9701 JWT Introspection Response (opt-in).
    /// When enabled + client sends Accept: application/token-introspection+jwt,
    /// the introspection response is a signed JWT instead of plain JSON.
    pub enable_jwt_introspection: bool,
    /// Maximum lifetime of the JWT introspection response JWT (seconds).
    /// JI-2 threat model: MUST be ≤ 60 to limit replay window.
    pub jwt_introspection_exp_secs: u64,
    pub jwt_leeway_secs: u64,
    /// RFC 9396 Rich Authorization Requests: supported `authorization_details` types (CSV list).
    pub authorization_details_types_supported: Vec<String>,
    /// RFC 9470 Step-Up: supported ACR values (CSV list).
    pub acr_values_supported: Vec<String>,
    /// Default ACR applied when none is requested.
    pub default_acr: Option<String>,
    /// ACR that the local password credential flow is allowed to assert.
    pub local_password_acr: Option<String>,
    /// RFC 9470 Step-Up challenge lifetime in seconds.
    pub stepup_challenge_ttl_secs: u64,
    /// Upstream OIDC authorize callback state lifetime in seconds.
    pub upstream_auth_ttl_secs: u64,
    /// Upstream logout relay state lifetime in seconds.
    pub upstream_logout_relay_ttl_secs: u64,
    /// Operator-managed outbound domain allowlist for upstream OIDC provider HTTP calls.
    pub upstream_outbound_allowed_domains: Vec<String>,

    /// Access token TTL in seconds (default 3600 = 1 hour).
    pub access_token_ttl_secs: u64,
    /// Refresh token TTL in seconds (default 86400 = 24 hours).
    pub refresh_token_ttl_secs: u64,
    /// Authorization code lifetime in seconds (default 300 = 5 minutes).
    pub authorization_code_ttl_secs: u64,
    /// PAR request_uri lifetime in seconds (default 90).
    pub par_expires_in_secs: u64,
    /// RFC 8628 device_code/user_code lifetime in seconds.
    pub device_code_ttl_secs: u64,
    /// RFC 8628 default polling interval in seconds.
    pub device_code_poll_interval_secs: u64,
    /// Client assertion/JWT bearer replay window in seconds (default 300).
    pub pkjwt_jti_window_secs: i64,
    /// JWT Bearer assertion replay window in seconds (default 300).
    pub jwt_bearer_jti_window_secs: i64,
    /// Request Object jti replay window in seconds (default 600).
    pub request_object_jti_ttl_secs: u64,

    // Transport security enforcement (Forwarded/TLS requirements)
    pub transport: TransportSecurityConfig,

    // RFC 8705 metadata posture for deployments that terminate mTLS at a trusted boundary.
    pub mtls_enabled: bool,
    pub mtls_alias_par: bool,
    pub mtls_base_url: Option<String>,

    // Global security policy (RFC 9700)
    pub security_policy: SecurityPolicy,

    // Maximum length for Base64URL-encoded JOSE protected headers
    pub jose_header_max_len: usize,
    pub dcr_everparse_runtime_enabled: bool,
    pub request_object_everparse_runtime_enabled: bool,

    // Required database configuration (SQLx/PostgreSQL)
    pub database: DatabaseConfig,

    /// Crypto profile: `Verified` (HACL*/`EverCrypt` only).
    /// Management-database authority hydrates this from `policy.cryptoProfile`.
    pub crypto_profile: CryptoProfile,

    /// Runtime-state and configuration-authority boundary checks.
    pub runtime_state_boundary: RuntimeStateBoundaryConfig,
}

impl ServerConfig {
    #[must_use]
    pub fn upstream(&self) -> UpstreamRuntimeConfig<'_> {
        UpstreamRuntimeConfig::new(
            self.upstream_auth_ttl_secs,
            self.upstream_logout_relay_ttl_secs,
            &self.upstream_outbound_allowed_domains,
        )
    }

    fn baseline_with_database(
        runtime_state_boundary: RuntimeStateBoundaryConfig,
        database: DatabaseConfig,
    ) -> Self {
        let security_policy = SecurityPolicy::default();
        let mut transport = TransportSecurityConfig::default();
        transport.apply_security_policy(&security_policy);

        Self {
            strict_authorize_redirect: true,
            require_state: true,
            require_pushed_authorization_requests: false,
            require_client_auth_introspection: true,
            require_client_auth_revocation: true,
            require_client_auth_par: true,
            require_client_auth_token: true,
            dpop_strict: true,
            dpop_iat_window_secs: 300,
            require_dpop_nonce: true,
            dpop_nonce_ttl_secs: 300,
            enable_private_key_jwt: false,
            enable_jwt_bearer_grant: false,
            allow_jwt_bearer_client_subject: false,
            enable_token_exchange: false,
            enable_device_authz: false,
            allowed_grant_types: default_grant_types(),
            enable_jwt_access_tokens: false,
            enable_jwt_introspection: false,
            jwt_introspection_exp_secs: DEFAULT_JWT_INTROSPECTION_EXP_SECS,
            jwt_leeway_secs: 60,
            authorization_details_types_supported: Vec::new(),
            acr_values_supported: Vec::new(),
            default_acr: None,
            local_password_acr: None,
            stepup_challenge_ttl_secs: DEFAULT_STEPUP_CHALLENGE_TTL_SECS,
            upstream_auth_ttl_secs: DEFAULT_UPSTREAM_AUTH_TTL_SECS,
            upstream_logout_relay_ttl_secs: DEFAULT_UPSTREAM_LOGOUT_RELAY_TTL_SECS,
            upstream_outbound_allowed_domains: Vec::new(),
            access_token_ttl_secs: 3600,
            refresh_token_ttl_secs: 86400,
            authorization_code_ttl_secs: DEFAULT_AUTHORIZATION_CODE_TTL_SECS,
            par_expires_in_secs: DEFAULT_PAR_EXPIRES_IN_SECS,
            device_code_ttl_secs: DEFAULT_DEVICE_CODE_TTL_SECS,
            device_code_poll_interval_secs: DEFAULT_DEVICE_CODE_POLL_INTERVAL_SECS,
            pkjwt_jti_window_secs: DEFAULT_CLIENT_ASSERTION_REPLAY_WINDOW_SECS,
            jwt_bearer_jti_window_secs: DEFAULT_CLIENT_ASSERTION_REPLAY_WINDOW_SECS,
            request_object_jti_ttl_secs: DEFAULT_REQUEST_OBJECT_JTI_TTL_SECS,
            transport,
            mtls_enabled: false,
            mtls_alias_par: false,
            mtls_base_url: None,
            security_policy,
            jose_header_max_len: jose_policy::DEFAULT_HEADER_MAX_LEN,
            dcr_everparse_runtime_enabled: false,
            request_object_everparse_runtime_enabled: false,
            database,
            crypto_profile: CryptoProfile::Verified,
            runtime_state_boundary,
        }
    }
}

#[cfg(test)]
impl Default for ServerConfig {
    fn default() -> Self {
        Self::baseline_with_database(RuntimeStateBoundaryConfig, DatabaseConfig::default())
    }
}

#[cfg(any(test, kani))]
impl ServerConfig {
    pub fn try_from_env() -> Result<Self, ConfigError> {
        BootstrapConfig::try_from_env().map(BootstrapConfig::into_runtime_baseline)
    }
}

fn try_validate_acr_config(
    supported: &[String],
    configured: Option<&str>,
) -> Result<(), ConfigError> {
    let Some(configured) = configured else {
        return Ok(());
    };
    if supported.is_empty() || supported.iter().any(|value| value == configured) {
        return Ok(());
    }
    Err(ConfigError::InvalidAcr {
        configured: configured.to_string(),
    })
}

#[cfg(test)]
mod tests;
