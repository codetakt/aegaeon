use super::types::OAuthProfileInput;
use crate::management::types::{OAuthProfile, UpdateOAuthProfileRequest};
use crate::web::management::{normalize_optional_text, normalize_text};

pub(in crate::web::management) fn oauth_profile_input_from_update(
    existing: &OAuthProfile,
    req: &UpdateOAuthProfileRequest,
) -> OAuthProfileInput {
    let description = match req.description.as_deref() {
        Some(value) => normalize_optional_text(Some(value)),
        None => existing.description.clone(),
    };
    let expires_at = match req.expires_at.as_deref() {
        Some(value) => normalize_optional_text(Some(value)),
        None => existing.expires_at.clone(),
    };

    OAuthProfileInput {
        name: req
            .name
            .as_deref()
            .map_or_else(|| existing.name.clone(), normalize_text),
        description,
        profile_type: req
            .profile_type
            .as_deref()
            .map_or_else(|| existing.profile_type.clone(), normalize_text),
        is_default: req.is_default.unwrap_or(existing.is_default),
        require_pkce: req.require_pkce.unwrap_or(existing.require_pkce),
        require_state_parameter: req
            .require_state_parameter
            .unwrap_or(existing.require_state_parameter),
        require_iss_parameter: req
            .require_iss_parameter
            .unwrap_or(existing.require_iss_parameter),
        sender_constrained: req
            .sender_constrained
            .as_deref()
            .map_or_else(|| existing.sender_constrained.clone(), normalize_text),
        enforce_refresh_sender_binding: req
            .enforce_refresh_sender_binding
            .unwrap_or(existing.enforce_refresh_sender_binding),
        allowed_grant_types: req
            .allowed_grant_types
            .clone()
            .unwrap_or_else(|| existing.allowed_grant_types.clone()),
        token_endpoint_auth_methods_allowed: req
            .token_endpoint_auth_methods_allowed
            .clone()
            .unwrap_or_else(|| existing.token_endpoint_auth_methods_allowed.clone()),
        expires_at,
    }
}
