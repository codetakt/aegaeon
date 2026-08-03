use super::decoder::PolicyRowDecoder;
use axum::response::Response;

pub(super) struct DcrSsaPolicyFields {
    pub(super) dcr_require_pkce_for_public: bool,
    pub(super) dcr_require_pkce_for_confidential: bool,
    pub(super) dcr_require_sender_constrained: bool,
    pub(super) dcr_allowed_sender_methods: Vec<String>,
    pub(super) ssa_jwt_pem: Option<String>,
    pub(super) ssa_expected_iss: Option<String>,
    pub(super) ssa_expected_aud: Option<String>,
    pub(super) ssa_leeway_seconds: u32,
}

pub(super) fn read_dcr_ssa_policy_fields(
    decoder: &PolicyRowDecoder<'_>,
) -> Result<DcrSsaPolicyFields, Response> {
    Ok(DcrSsaPolicyFields {
        dcr_require_pkce_for_public: decoder.bool_field("dcr_require_pkce_for_public")?,
        dcr_require_pkce_for_confidential: decoder
            .bool_field("dcr_require_pkce_for_confidential")?,
        dcr_require_sender_constrained: decoder.bool_field("dcr_require_sender_constrained")?,
        dcr_allowed_sender_methods: decoder.vec_field("dcr_allowed_sender_methods")?,
        ssa_jwt_pem: decoder.optional_text_field("ssa_jwt_pem")?,
        ssa_expected_iss: decoder.optional_text_field("ssa_expected_iss")?,
        ssa_expected_aud: decoder.optional_text_field("ssa_expected_aud")?,
        ssa_leeway_seconds: decoder.seconds_field("ssa_leeway_seconds", 0)?,
    })
}
