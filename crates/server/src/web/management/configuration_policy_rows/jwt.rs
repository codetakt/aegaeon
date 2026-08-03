use super::decoder::PolicyRowDecoder;
use axum::response::Response;

pub(super) struct JwtPolicyFields {
    pub(super) jwt_bearer_allow_client_subject: bool,
    pub(super) jwt_bearer_jti_window_seconds: u32,
    pub(super) request_object_jti_ttl_seconds: u32,
    pub(super) request_object_everparse_runtime_enabled: bool,
    pub(super) jwt_access_tokens_enabled: bool,
    pub(super) jwt_introspection_enabled: bool,
    pub(super) jwt_introspection_exp_seconds: u32,
    pub(super) authorization_details_types_supported: Vec<String>,
    pub(super) acr_values_supported: Vec<String>,
    pub(super) default_acr: Option<String>,
    pub(super) local_password_acr: Option<String>,
}

pub(super) fn read_jwt_policy_fields(
    decoder: &PolicyRowDecoder<'_>,
) -> Result<JwtPolicyFields, Response> {
    Ok(JwtPolicyFields {
        jwt_bearer_allow_client_subject: decoder.bool_field("jwt_bearer_allow_client_subject")?,
        jwt_bearer_jti_window_seconds: decoder.seconds_field("jwt_bearer_jti_window_seconds", 1)?,
        request_object_jti_ttl_seconds: decoder
            .seconds_field("request_object_jti_ttl_seconds", 1)?,
        request_object_everparse_runtime_enabled: decoder
            .bool_field("request_object_everparse_runtime_enabled")?,
        jwt_access_tokens_enabled: decoder.bool_field("jwt_access_tokens_enabled")?,
        jwt_introspection_enabled: decoder.bool_field("jwt_introspection_enabled")?,
        jwt_introspection_exp_seconds: decoder.seconds_field("jwt_introspection_exp_seconds", 1)?,
        authorization_details_types_supported: decoder
            .vec_field("authorization_details_types_supported")?,
        acr_values_supported: decoder.vec_field("acr_values_supported")?,
        default_acr: decoder.optional_text_field("default_acr")?,
        local_password_acr: decoder.optional_text_field("local_password_acr")?,
    })
}
