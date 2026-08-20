mod base;
mod dcr_ssa;
mod decoder;
mod federation;
mod jwks;
mod jwt;
mod oidc_mtls;
mod runtime;

use crate::management::types::PolicyDocument;
use axum::response::Response;
use decoder::PolicyRowDecoder;
use sqlx::postgres::PgRow;

#[expect(
    clippy::too_many_lines,
    reason = "existing exhaustive database mapping; new oversized functions remain gated"
)]
pub(super) fn policy_document_from_environment_policy_row(
    row: &PgRow,
    request_id: &str,
) -> Result<PolicyDocument, Response> {
    let decoder = PolicyRowDecoder::new(row, request_id);
    let base = base::read_base_policy_fields(&decoder)?;
    let jwks = jwks::read_jwks_policy_fields(&decoder)?;
    let jwt = jwt::read_jwt_policy_fields(&decoder)?;
    let dcr_ssa = dcr_ssa::read_dcr_ssa_policy_fields(&decoder)?;
    let oidc_mtls = oidc_mtls::read_oidc_mtls_policy_fields(&decoder)?;
    let federation = federation::read_federation_policy_fields(&decoder)?;
    let runtime = runtime::read_runtime_policy_fields(&decoder)?;

    Ok(PolicyDocument {
        pkce_required: base.pkce_required,
        dcr_enabled: base.dcr_enabled,
        dcr_everparse_runtime_enabled: base.dcr_everparse_runtime_enabled,
        require_state_parameter: base.require_state_parameter,
        strict_authorize_redirect: base.strict_authorize_redirect,
        require_client_auth_token: base.require_client_auth_token,
        require_client_auth_par: base.require_client_auth_par,
        require_client_auth_introspection: base.require_client_auth_introspection,
        require_client_auth_revocation: base.require_client_auth_revocation,
        sender_constraint: base.sender_constraint,
        require_scope_subset: base.require_scope_subset,
        require_audience_match: base.require_audience_match,
        retain_refresh_chain: base.retain_refresh_chain,
        enforce_refresh_sender_binding: base.enforce_refresh_sender_binding,
        dpop_strict: base.dpop_strict,
        dpop_iat_window_seconds: base.dpop_iat_window_seconds,
        dpop_require_nonce: base.dpop_require_nonce,
        dpop_nonce_ttl_seconds: base.dpop_nonce_ttl_seconds,
        require_pushed_authorization_requests: base.require_pushed_authorization_requests,
        par_expires_in_seconds: base.par_expires_in_seconds,
        device_code_ttl_seconds: base.device_code_ttl_seconds,
        device_code_poll_interval_seconds: base.device_code_poll_interval_seconds,
        activation_token_default_ttl_seconds: base.activation_token_default_ttl_seconds,
        password_reset_token_default_ttl_seconds: base.password_reset_token_default_ttl_seconds,
        recovery_token_max_ttl_seconds: base.recovery_token_max_ttl_seconds,
        client_secret_default_expiration_days: base.client_secret_default_expiration_days,
        client_secret_max_expiration_days: base.client_secret_max_expiration_days,
        private_key_jwt_enabled: base.private_key_jwt_enabled,
        client_jwt_allowed_algs: base.client_jwt_allowed_algs,
        client_jwt_require_kid: base.client_jwt_require_kid,
        jwt_leeway_seconds: base.jwt_leeway_seconds,
        pkjwt_jti_window_seconds: base.pkjwt_jti_window_seconds,
        jose_header_max_len: base.jose_header_max_len,
        jwks_allow_kid_reuse: jwks.jwks_allow_kid_reuse,
        jwks_circuit_open_fails: jwks.jwks_circuit_open_fails,
        jwks_circuit_reset_seconds: jwks.jwks_circuit_reset_seconds,
        jwks_cache_ttl_seconds: jwks.jwks_cache_ttl_seconds,
        jwks_cache_gc_interval_seconds: jwks.jwks_cache_gc_interval_seconds,
        jwks_local_cache_max_entries: jwks.jwks_local_cache_max_entries,
        jwks_http_timeout_seconds: jwks.jwks_http_timeout_seconds,
        jwks_refresh_skew_seconds: jwks.jwks_refresh_skew_seconds,
        jwks_shared_state_max_age_seconds: jwks.jwks_shared_state_max_age_seconds,
        jwks_max_body_bytes: jwks.jwks_max_body_bytes,
        jwks_http_retries: jwks.jwks_http_retries,
        jwt_bearer_allow_client_subject: jwt.jwt_bearer_allow_client_subject,
        jwt_bearer_jti_window_seconds: jwt.jwt_bearer_jti_window_seconds,
        request_object_jti_ttl_seconds: jwt.request_object_jti_ttl_seconds,
        request_object_everparse_runtime_enabled: jwt.request_object_everparse_runtime_enabled,
        jwt_access_tokens_enabled: jwt.jwt_access_tokens_enabled,
        jwt_introspection_enabled: jwt.jwt_introspection_enabled,
        jwt_introspection_exp_seconds: jwt.jwt_introspection_exp_seconds,
        authorization_details_types_supported: jwt.authorization_details_types_supported,
        acr_values_supported: jwt.acr_values_supported,
        default_acr: jwt.default_acr,
        local_password_acr: jwt.local_password_acr,
        dcr_require_pkce_for_public: dcr_ssa.dcr_require_pkce_for_public,
        dcr_require_pkce_for_confidential: dcr_ssa.dcr_require_pkce_for_confidential,
        dcr_require_sender_constrained: dcr_ssa.dcr_require_sender_constrained,
        dcr_allowed_sender_methods: dcr_ssa.dcr_allowed_sender_methods,
        ssa_jwt_pem: dcr_ssa.ssa_jwt_pem,
        ssa_expected_iss: dcr_ssa.ssa_expected_iss,
        ssa_expected_aud: dcr_ssa.ssa_expected_aud,
        ssa_leeway_seconds: dcr_ssa.ssa_leeway_seconds,
        oidc_enabled: oidc_mtls.oidc_enabled,
        oidc_enable_discovery: oidc_mtls.oidc_enable_discovery,
        oidc_enable_userinfo: oidc_mtls.oidc_enable_userinfo,
        oidc_enable_logout: oidc_mtls.oidc_enable_logout,
        oidc_enable_backchannel_logout: oidc_mtls.oidc_enable_backchannel_logout,
        oidc_logout_session_ttl_seconds: oidc_mtls.oidc_logout_session_ttl_seconds,
        oidc_backchannel_logout_timeout_seconds: oidc_mtls.oidc_backchannel_logout_timeout_seconds,
        oidc_require_nonce: oidc_mtls.oidc_require_nonce,
        mtls_enabled: oidc_mtls.mtls_enabled,
        mtls_base_url: oidc_mtls.mtls_base_url,
        mtls_alias_par_enabled: oidc_mtls.mtls_alias_par_enabled,
        federation_outbound_allowed_domains: federation.federation_outbound_allowed_domains,
        upstream_outbound_allowed_domains: federation.upstream_outbound_allowed_domains,
        federation_entity_cache_ttl_seconds: federation.federation_entity_cache_ttl_seconds,
        federation_trust_chain_cache_ttl_seconds: federation
            .federation_trust_chain_cache_ttl_seconds,
        federation_cache_max_entries: federation.federation_cache_max_entries,
        crypto_profile: runtime.crypto_profile,
        allowed_signing_algorithms: runtime.allowed_signing_algorithms,
        allowed_grant_types: runtime.allowed_grant_types,
        access_token_time_to_live_seconds: runtime.access_token_time_to_live_seconds,
        id_token_time_to_live_seconds: runtime.id_token_time_to_live_seconds,
        refresh_token_time_to_live_seconds: runtime.refresh_token_time_to_live_seconds,
        authorization_code_time_to_live_seconds: runtime.authorization_code_time_to_live_seconds,
        auth_session_ttl_seconds: runtime.auth_session_ttl_seconds,
        auth_max_sessions: runtime.auth_max_sessions,
        stepup_challenge_ttl_seconds: runtime.stepup_challenge_ttl_seconds,
        upstream_auth_ttl_seconds: runtime.upstream_auth_ttl_seconds,
        upstream_logout_relay_ttl_seconds: runtime.upstream_logout_relay_ttl_seconds,
        upstream_discovery_cache_ttl_seconds: runtime.upstream_discovery_cache_ttl_seconds,
        upstream_discovery_cache_max_entries: runtime.upstream_discovery_cache_max_entries,
        upstream_jwks_cache_ttl_seconds: runtime.upstream_jwks_cache_ttl_seconds,
        upstream_jwks_cache_max_entries: runtime.upstream_jwks_cache_max_entries,
        cleanup_interval_seconds: runtime.cleanup_interval_seconds,
        runtime_config_monitor_interval_seconds: runtime.runtime_config_monitor_interval_seconds,
    })
}
