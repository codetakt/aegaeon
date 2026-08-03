use super::super::Environment;
use super::document::{PolicyDocument, PolicySenderConstraint};
use super::runtime::RuntimeActivationStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyPatchRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkce_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcr_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcr_everparse_runtime_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_state_parameter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_authorize_redirect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_client_auth_token: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_client_auth_par: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_client_auth_introspection: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_client_auth_revocation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_constraint: Option<PolicySenderConstraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_scope_subset: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_audience_match: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_refresh_chain: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforce_refresh_sender_binding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_strict: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_iat_window_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_require_nonce: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_nonce_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_pushed_authorization_requests: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub par_expires_in_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_code_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_code_poll_interval_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_token_default_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_reset_token_default_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_token_max_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_default_expiration_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_max_expiration_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_jwt_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_jwt_allowed_algs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_jwt_require_kid: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_leeway_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkjwt_jti_window_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jose_header_max_len: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_allow_kid_reuse: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_circuit_open_fails: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_circuit_reset_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_cache_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_cache_gc_interval_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_local_cache_max_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_http_timeout_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_refresh_skew_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_shared_state_max_age_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_max_body_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_http_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_bearer_allow_client_subject: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_bearer_jti_window_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_object_jti_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_object_everparse_runtime_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_access_tokens_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_introspection_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_introspection_exp_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_password_acr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcr_require_pkce_for_public: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcr_require_pkce_for_confidential: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcr_require_sender_constrained: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcr_allowed_sender_methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssa_jwt_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssa_expected_iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssa_expected_aud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssa_leeway_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_enable_discovery: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_enable_userinfo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_enable_logout: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_enable_backchannel_logout: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_logout_session_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_backchannel_logout_timeout_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_require_nonce: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_alias_par_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_outbound_allowed_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_outbound_allowed_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_entity_cache_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_trust_chain_cache_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_cache_max_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_signing_algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_grant_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_time_to_live_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_time_to_live_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token_time_to_live_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_code_time_to_live_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_session_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_max_sessions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stepup_challenge_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_auth_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_logout_relay_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_discovery_cache_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_discovery_cache_max_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_jwks_cache_ttl_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_jwks_cache_max_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_interval_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_config_monitor_interval_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_security_downgrade: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PolicyPatchResponse {
    pub policy: PolicyDocument,
    pub environment: Environment,
    pub runtime_activation: RuntimeActivationStatus,
}
