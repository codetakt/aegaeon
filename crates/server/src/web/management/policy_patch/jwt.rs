use super::super::{normalize_optional_text, normalize_trimmed_list};
use crate::management::types::{PolicyDocument, PolicyPatchRequest};

pub(super) fn apply_jwt_policy_patch(policy: &mut PolicyDocument, patch: &PolicyPatchRequest) {
    if let Some(value) = patch.jwt_bearer_allow_client_subject {
        policy.jwt_bearer_allow_client_subject = value;
    }
    if let Some(value) = patch.jwt_bearer_jti_window_seconds {
        policy.jwt_bearer_jti_window_seconds = value;
    }
    if let Some(value) = patch.request_object_jti_ttl_seconds {
        policy.request_object_jti_ttl_seconds = value;
    }
    if let Some(value) = patch.request_object_everparse_runtime_enabled {
        policy.request_object_everparse_runtime_enabled = value;
    }
    if let Some(value) = patch.jwt_access_tokens_enabled {
        policy.jwt_access_tokens_enabled = value;
    }
    if let Some(value) = patch.jwt_introspection_enabled {
        policy.jwt_introspection_enabled = value;
    }
    if let Some(value) = patch.jwt_introspection_exp_seconds {
        policy.jwt_introspection_exp_seconds = value;
    }
    if let Some(value) = patch.authorization_details_types_supported.as_ref() {
        policy.authorization_details_types_supported = normalize_trimmed_list(value);
    }
    if let Some(value) = patch.acr_values_supported.as_ref() {
        policy.acr_values_supported = normalize_trimmed_list(value);
    }
    if let Some(value) = patch.default_acr.as_deref() {
        policy.default_acr = normalize_optional_text(Some(value));
    }
    if let Some(value) = patch.local_password_acr.as_deref() {
        policy.local_password_acr = normalize_optional_text(Some(value));
    }
}
