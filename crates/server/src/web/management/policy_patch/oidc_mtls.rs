use super::super::normalize_optional_text;
use crate::management::types::{PolicyDocument, PolicyPatchRequest};

pub(super) fn apply_oidc_mtls_policy_patch(
    policy: &mut PolicyDocument,
    patch: &PolicyPatchRequest,
) {
    if let Some(value) = patch.oidc_enabled {
        policy.oidc_enabled = value;
    }
    if let Some(value) = patch.oidc_enable_discovery {
        policy.oidc_enable_discovery = value;
    }
    if let Some(value) = patch.oidc_enable_userinfo {
        policy.oidc_enable_userinfo = value;
    }
    if let Some(value) = patch.oidc_enable_logout {
        policy.oidc_enable_logout = value;
    }
    if let Some(value) = patch.oidc_enable_backchannel_logout {
        policy.oidc_enable_backchannel_logout = value;
    }
    if let Some(value) = patch.oidc_logout_session_ttl_seconds {
        policy.oidc_logout_session_ttl_seconds = value;
    }
    if let Some(value) = patch.oidc_backchannel_logout_timeout_seconds {
        policy.oidc_backchannel_logout_timeout_seconds = value;
    }
    if let Some(value) = patch.oidc_require_nonce {
        policy.oidc_require_nonce = value;
    }

    if let Some(value) = patch.mtls_enabled {
        policy.mtls_enabled = value;
    }
    if let Some(value) = patch.mtls_base_url.as_deref() {
        policy.mtls_base_url = normalize_optional_text(Some(value));
    }
    if let Some(value) = patch.mtls_alias_par_enabled {
        policy.mtls_alias_par_enabled = value;
    }
}
