use super::defaults::*;
use crate::policy::SenderConstraint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum PolicySenderConstraint {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "dpop")]
    #[default]
    Dpop,
    #[serde(rename = "mtls")]
    Mtls,
}

impl PolicySenderConstraint {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Dpop => "DPOP",
            Self::Mtls => "MTLS",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "NONE" => Some(Self::None),
            "DPOP" => Some(Self::Dpop),
            "MTLS" => Some(Self::Mtls),
            _ => None,
        }
    }
}

impl From<PolicySenderConstraint> for SenderConstraint {
    fn from(value: PolicySenderConstraint) -> Self {
        match value {
            PolicySenderConstraint::None => Self::None,
            PolicySenderConstraint::Dpop => Self::DPoP,
            PolicySenderConstraint::Mtls => Self::Mtls,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // This DTO intentionally exposes each policy toggle independently for auditability.
pub struct PolicyDocument {
    pub pkce_required: bool,
    pub dcr_enabled: bool,
    pub dcr_everparse_runtime_enabled: bool,
    pub require_state_parameter: bool,
    pub strict_authorize_redirect: bool,
    pub require_client_auth_token: bool,
    pub require_client_auth_par: bool,
    pub require_client_auth_introspection: bool,
    pub require_client_auth_revocation: bool,
    pub sender_constraint: PolicySenderConstraint,
    pub require_scope_subset: bool,
    pub require_audience_match: bool,
    pub retain_refresh_chain: bool,
    pub enforce_refresh_sender_binding: bool,
    pub dpop_strict: bool,
    pub dpop_iat_window_seconds: u32,
    pub dpop_require_nonce: bool,
    pub dpop_nonce_ttl_seconds: u32,
    pub require_pushed_authorization_requests: bool,
    pub par_expires_in_seconds: u32,
    pub device_code_ttl_seconds: u32,
    pub device_code_poll_interval_seconds: u32,
    pub activation_token_default_ttl_seconds: u32,
    pub password_reset_token_default_ttl_seconds: u32,
    pub recovery_token_max_ttl_seconds: u32,
    pub client_secret_default_expiration_days: u32,
    pub client_secret_max_expiration_days: u32,
    pub private_key_jwt_enabled: bool,
    pub client_jwt_allowed_algs: Vec<String>,
    pub client_jwt_require_kid: bool,
    pub jwt_leeway_seconds: u32,
    pub pkjwt_jti_window_seconds: u32,
    pub jose_header_max_len: u32,
    pub jwks_allow_kid_reuse: bool,
    pub jwks_circuit_open_fails: u32,
    pub jwks_circuit_reset_seconds: u32,
    pub jwks_cache_ttl_seconds: u32,
    pub jwks_cache_gc_interval_seconds: u32,
    pub jwks_local_cache_max_entries: u32,
    pub jwks_http_timeout_seconds: u32,
    pub jwks_refresh_skew_seconds: u32,
    pub jwks_shared_state_max_age_seconds: u32,
    pub jwks_max_body_bytes: u32,
    pub jwks_http_retries: u32,
    pub jwt_bearer_allow_client_subject: bool,
    pub jwt_bearer_jti_window_seconds: u32,
    pub request_object_jti_ttl_seconds: u32,
    pub request_object_everparse_runtime_enabled: bool,
    pub jwt_access_tokens_enabled: bool,
    pub jwt_introspection_enabled: bool,
    pub jwt_introspection_exp_seconds: u32,
    pub authorization_details_types_supported: Vec<String>,
    pub acr_values_supported: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_password_acr: Option<String>,
    pub dcr_require_pkce_for_public: bool,
    pub dcr_require_pkce_for_confidential: bool,
    pub dcr_require_sender_constrained: bool,
    pub dcr_allowed_sender_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssa_jwt_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssa_expected_iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssa_expected_aud: Option<String>,
    pub ssa_leeway_seconds: u32,
    pub oidc_enabled: bool,
    pub oidc_enable_discovery: bool,
    pub oidc_enable_userinfo: bool,
    pub oidc_enable_logout: bool,
    pub oidc_enable_backchannel_logout: bool,
    pub oidc_logout_session_ttl_seconds: u32,
    pub oidc_backchannel_logout_timeout_seconds: u32,
    pub oidc_require_nonce: bool,
    pub mtls_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_base_url: Option<String>,
    pub mtls_alias_par_enabled: bool,
    pub federation_outbound_allowed_domains: Vec<String>,
    pub upstream_outbound_allowed_domains: Vec<String>,
    pub federation_entity_cache_ttl_seconds: u32,
    pub federation_trust_chain_cache_ttl_seconds: u32,
    pub federation_cache_max_entries: u32,
    pub crypto_profile: String,
    pub allowed_signing_algorithms: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub access_token_time_to_live_seconds: u32,
    pub id_token_time_to_live_seconds: u32,
    pub refresh_token_time_to_live_seconds: u32,
    pub authorization_code_time_to_live_seconds: u32,
    pub auth_session_ttl_seconds: u32,
    pub auth_max_sessions: u32,
    pub stepup_challenge_ttl_seconds: u32,
    pub upstream_auth_ttl_seconds: u32,
    pub upstream_logout_relay_ttl_seconds: u32,
    pub upstream_discovery_cache_ttl_seconds: u32,
    pub upstream_discovery_cache_max_entries: u32,
    pub upstream_jwks_cache_ttl_seconds: u32,
    pub upstream_jwks_cache_max_entries: u32,
    pub cleanup_interval_seconds: u32,
    pub runtime_config_monitor_interval_seconds: u32,
}

impl Default for PolicyDocument {
    #[expect(
        clippy::too_many_lines,
        reason = "existing exhaustive default policy literal; new oversized functions remain gated"
    )]
    fn default() -> Self {
        Self {
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
            device_code_ttl_seconds: default_device_code_ttl_seconds(),
            device_code_poll_interval_seconds: default_device_code_poll_interval_seconds(),
            activation_token_default_ttl_seconds: default_activation_token_ttl_seconds(),
            password_reset_token_default_ttl_seconds: default_password_reset_token_ttl_seconds(),
            recovery_token_max_ttl_seconds: default_recovery_token_max_ttl_seconds(),
            client_secret_default_expiration_days: default_client_secret_expiration_days(),
            client_secret_max_expiration_days: default_client_secret_max_expiration_days(),
            private_key_jwt_enabled: false,
            client_jwt_allowed_algs: vec!["RS256".to_string()],
            client_jwt_require_kid: false,
            jwt_leeway_seconds: 60,
            pkjwt_jti_window_seconds: 300,
            jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN as u32,
            jwks_allow_kid_reuse: false,
            jwks_circuit_open_fails: default_jwks_circuit_open_fails(),
            jwks_circuit_reset_seconds: default_jwks_circuit_reset_seconds(),
            jwks_cache_ttl_seconds: default_jwks_cache_ttl_seconds(),
            jwks_cache_gc_interval_seconds: default_jwks_cache_gc_interval_seconds(),
            jwks_local_cache_max_entries: default_jwks_local_cache_max_entries(),
            jwks_http_timeout_seconds: default_jwks_http_timeout_seconds(),
            jwks_refresh_skew_seconds: default_jwks_refresh_skew_seconds(),
            jwks_shared_state_max_age_seconds: default_jwks_shared_state_max_age_seconds(),
            jwks_max_body_bytes: default_jwks_max_body_bytes(),
            jwks_http_retries: default_jwks_http_retries(),
            jwt_bearer_allow_client_subject: false,
            jwt_bearer_jti_window_seconds: default_jwt_bearer_jti_window_seconds(),
            request_object_jti_ttl_seconds: 600,
            request_object_everparse_runtime_enabled: false,
            jwt_access_tokens_enabled: false,
            jwt_introspection_enabled: false,
            jwt_introspection_exp_seconds: default_jwt_introspection_exp_seconds(),
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
            oidc_enabled: false,
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
            federation_entity_cache_ttl_seconds: default_federation_entity_cache_ttl_seconds(),
            federation_trust_chain_cache_ttl_seconds:
                default_federation_trust_chain_cache_ttl_seconds(),
            federation_cache_max_entries: default_federation_cache_max_entries(),
            crypto_profile: default_crypto_profile(),
            allowed_signing_algorithms: vec!["RS256".to_string(), "EdDSA".to_string()],
            allowed_grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "client_credentials".to_string(),
            ],
            access_token_time_to_live_seconds: 3600,
            id_token_time_to_live_seconds: 3600,
            refresh_token_time_to_live_seconds: 2_592_000,
            authorization_code_time_to_live_seconds: 300,
            auth_session_ttl_seconds: default_auth_session_ttl_seconds(),
            auth_max_sessions: default_auth_max_sessions(),
            stepup_challenge_ttl_seconds: default_stepup_challenge_ttl_seconds(),
            upstream_auth_ttl_seconds: default_upstream_auth_ttl_seconds(),
            upstream_logout_relay_ttl_seconds: default_upstream_logout_relay_ttl_seconds(),
            upstream_discovery_cache_ttl_seconds: default_upstream_metadata_cache_ttl_seconds(),
            upstream_discovery_cache_max_entries: default_upstream_metadata_cache_max_entries(),
            upstream_jwks_cache_ttl_seconds: default_upstream_metadata_cache_ttl_seconds(),
            upstream_jwks_cache_max_entries: default_upstream_metadata_cache_max_entries(),
            cleanup_interval_seconds: default_cleanup_interval_seconds(),
            runtime_config_monitor_interval_seconds: default_runtime_sync_interval_seconds(),
        }
    }
}
