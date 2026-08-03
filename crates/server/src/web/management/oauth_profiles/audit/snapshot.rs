use super::super::super::oauth_profiles_support::OAuthProfileInput;
use crate::management::types::OAuthProfile;

pub(super) fn oauth_profile_audit_snapshot(profile: &OAuthProfile) -> serde_json::Value {
    serde_json::json!({
        "name": &profile.name,
        "description": &profile.description,
        "profileType": &profile.profile_type,
        "isDefault": profile.is_default,
        "requirePkce": profile.require_pkce,
        "requireStateParameter": profile.require_state_parameter,
        "requireIssParameter": profile.require_iss_parameter,
        "senderConstrained": &profile.sender_constrained,
        "enforceRefreshSenderBinding": profile.enforce_refresh_sender_binding,
        "allowedGrantTypes": &profile.allowed_grant_types,
        "tokenEndpointAuthMethodsAllowed": &profile.token_endpoint_auth_methods_allowed,
        "expiresAt": &profile.expires_at,
    })
}

pub(super) fn oauth_profile_input_audit_snapshot(input: &OAuthProfileInput) -> serde_json::Value {
    serde_json::json!({
        "name": &input.name,
        "description": &input.description,
        "profileType": &input.profile_type,
        "isDefault": input.is_default,
        "requirePkce": input.require_pkce,
        "requireStateParameter": input.require_state_parameter,
        "requireIssParameter": input.require_iss_parameter,
        "senderConstrained": &input.sender_constrained,
        "enforceRefreshSenderBinding": input.enforce_refresh_sender_binding,
        "allowedGrantTypes": &input.allowed_grant_types,
        "tokenEndpointAuthMethodsAllowed": &input.token_endpoint_auth_methods_allowed,
        "expiresAt": &input.expires_at,
    })
}
