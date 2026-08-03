use super::decoder::PolicyRowDecoder;
use crate::management::types::PolicySenderConstraint;
use axum::response::Response;

pub(super) struct BasePolicyFields {
    pub(super) pkce_required: bool,
    pub(super) dcr_enabled: bool,
    pub(super) dcr_everparse_runtime_enabled: bool,
    pub(super) require_state_parameter: bool,
    pub(super) strict_authorize_redirect: bool,
    pub(super) require_client_auth_token: bool,
    pub(super) require_client_auth_par: bool,
    pub(super) require_client_auth_introspection: bool,
    pub(super) require_client_auth_revocation: bool,
    pub(super) sender_constraint: PolicySenderConstraint,
    pub(super) require_scope_subset: bool,
    pub(super) require_audience_match: bool,
    pub(super) retain_refresh_chain: bool,
    pub(super) enforce_refresh_sender_binding: bool,
    pub(super) dpop_strict: bool,
    pub(super) dpop_iat_window_seconds: u32,
    pub(super) dpop_require_nonce: bool,
    pub(super) dpop_nonce_ttl_seconds: u32,
    pub(super) require_pushed_authorization_requests: bool,
    pub(super) par_expires_in_seconds: u32,
    pub(super) device_code_ttl_seconds: u32,
    pub(super) device_code_poll_interval_seconds: u32,
    pub(super) activation_token_default_ttl_seconds: u32,
    pub(super) password_reset_token_default_ttl_seconds: u32,
    pub(super) recovery_token_max_ttl_seconds: u32,
    pub(super) client_secret_default_expiration_days: u32,
    pub(super) client_secret_max_expiration_days: u32,
    pub(super) private_key_jwt_enabled: bool,
    pub(super) client_jwt_allowed_algs: Vec<String>,
    pub(super) client_jwt_require_kid: bool,
    pub(super) jwt_leeway_seconds: u32,
    pub(super) pkjwt_jti_window_seconds: u32,
    pub(super) jose_header_max_len: u32,
}

pub(super) fn read_base_policy_fields(
    decoder: &PolicyRowDecoder<'_>,
) -> Result<BasePolicyFields, Response> {
    Ok(BasePolicyFields {
        pkce_required: decoder.bool_field("pkce_required")?,
        dcr_enabled: decoder.bool_field("dcr_enabled")?,
        dcr_everparse_runtime_enabled: decoder.bool_field("dcr_everparse_runtime_enabled")?,
        require_state_parameter: decoder.bool_field("require_state_parameter")?,
        strict_authorize_redirect: decoder.bool_field("strict_authorize_redirect")?,
        require_client_auth_token: decoder.bool_field("require_client_auth_token")?,
        require_client_auth_par: decoder.bool_field("require_client_auth_par")?,
        require_client_auth_introspection: decoder
            .bool_field("require_client_auth_introspection")?,
        require_client_auth_revocation: decoder.bool_field("require_client_auth_revocation")?,
        sender_constraint: PolicySenderConstraint::from_db_str(
            &decoder.string_field("sender_constrained")?,
        )
        .ok_or_else(|| decoder.decode_error())?,
        require_scope_subset: decoder.bool_field("require_scope_subset")?,
        require_audience_match: decoder.bool_field("require_audience_match")?,
        retain_refresh_chain: decoder.bool_field("retain_refresh_chain")?,
        enforce_refresh_sender_binding: decoder.bool_field("enforce_refresh_sender_binding")?,
        dpop_strict: decoder.bool_field("dpop_strict")?,
        dpop_iat_window_seconds: decoder.seconds_field("dpop_iat_window_seconds", 0)?,
        dpop_require_nonce: decoder.bool_field("dpop_require_nonce")?,
        dpop_nonce_ttl_seconds: decoder.seconds_field("dpop_nonce_ttl_seconds", 1)?,
        require_pushed_authorization_requests: decoder
            .bool_field("require_pushed_authorization_requests")?,
        par_expires_in_seconds: decoder.seconds_field("par_expires_in_seconds", 1)?,
        device_code_ttl_seconds: decoder.seconds_field("device_code_ttl_seconds", 1)?,
        device_code_poll_interval_seconds: decoder
            .seconds_field("device_code_poll_interval_seconds", 1)?,
        activation_token_default_ttl_seconds: decoder
            .seconds_field("activation_token_default_ttl_seconds", 1)?,
        password_reset_token_default_ttl_seconds: decoder
            .seconds_field("password_reset_token_default_ttl_seconds", 1)?,
        recovery_token_max_ttl_seconds: decoder
            .seconds_field("recovery_token_max_ttl_seconds", 1)?,
        client_secret_default_expiration_days: decoder
            .u32_field("client_secret_default_expiration_days", 1)?,
        client_secret_max_expiration_days: decoder
            .u32_field("client_secret_max_expiration_days", 1)?,
        private_key_jwt_enabled: decoder.bool_field("private_key_jwt_enabled")?,
        client_jwt_allowed_algs: decoder.vec_field("client_jwt_allowed_algs")?,
        client_jwt_require_kid: decoder.bool_field("client_jwt_require_kid")?,
        jwt_leeway_seconds: decoder.seconds_field("jwt_leeway_seconds", 0)?,
        pkjwt_jti_window_seconds: decoder.seconds_field("pkjwt_jti_window_seconds", 1)?,
        jose_header_max_len: decoder.u32_field("jose_header_max_len", 1)?,
    })
}
