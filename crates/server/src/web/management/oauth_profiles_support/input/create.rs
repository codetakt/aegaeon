use super::types::OAuthProfileInput;
use crate::management::types::CreateOAuthProfileRequest;
use crate::web::management::normalize_optional_text;

pub(in crate::web::management) fn oauth_profile_input_from_create(
    req: &CreateOAuthProfileRequest,
) -> OAuthProfileInput {
    OAuthProfileInput {
        name: req.name.trim().to_string(),
        description: normalize_optional_text(req.description.as_deref()),
        profile_type: req.profile_type.trim().to_string(),
        is_default: req.is_default,
        require_pkce: req.require_pkce,
        require_state_parameter: req.require_state_parameter,
        require_iss_parameter: req.require_iss_parameter,
        sender_constrained: req.sender_constrained.trim().to_string(),
        enforce_refresh_sender_binding: req.enforce_refresh_sender_binding,
        allowed_grant_types: req.allowed_grant_types.clone(),
        token_endpoint_auth_methods_allowed: req.token_endpoint_auth_methods_allowed.clone(),
        expires_at: normalize_optional_text(req.expires_at.as_deref()),
    }
}
