use super::decoder::PolicyRowDecoder;
use axum::response::Response;

pub(super) struct OidcMtlsPolicyFields {
    pub(super) oidc_enabled: bool,
    pub(super) oidc_enable_discovery: bool,
    pub(super) oidc_enable_userinfo: bool,
    pub(super) oidc_enable_logout: bool,
    pub(super) oidc_enable_backchannel_logout: bool,
    pub(super) oidc_logout_session_ttl_seconds: u32,
    pub(super) oidc_backchannel_logout_timeout_seconds: u32,
    pub(super) oidc_require_nonce: bool,
    pub(super) mtls_enabled: bool,
    pub(super) mtls_base_url: Option<String>,
    pub(super) mtls_alias_par_enabled: bool,
}

pub(super) fn read_oidc_mtls_policy_fields(
    decoder: &PolicyRowDecoder<'_>,
) -> Result<OidcMtlsPolicyFields, Response> {
    Ok(OidcMtlsPolicyFields {
        oidc_enabled: decoder.bool_field("oidc_enabled")?,
        oidc_enable_discovery: decoder.bool_field("oidc_enable_discovery")?,
        oidc_enable_userinfo: decoder.bool_field("oidc_enable_userinfo")?,
        oidc_enable_logout: decoder.bool_field("oidc_enable_logout")?,
        oidc_enable_backchannel_logout: decoder.bool_field("oidc_enable_backchannel_logout")?,
        oidc_logout_session_ttl_seconds: decoder
            .seconds_field("oidc_logout_session_ttl_seconds", 1)?,
        oidc_backchannel_logout_timeout_seconds: decoder
            .seconds_field("oidc_backchannel_logout_timeout_seconds", 1)?,
        oidc_require_nonce: decoder.bool_field("oidc_require_nonce")?,
        mtls_enabled: decoder.bool_field("mtls_enabled")?,
        mtls_base_url: decoder.optional_text_field("mtls_base_url")?,
        mtls_alias_par_enabled: decoder.bool_field("mtls_alias_par_enabled")?,
    })
}
