use super::super::{normalize_lower_list, normalize_optional_text};
use crate::management::types::{PolicyDocument, PolicyPatchRequest};

pub(super) fn apply_dcr_ssa_policy_patch(policy: &mut PolicyDocument, patch: &PolicyPatchRequest) {
    if let Some(value) = patch.dcr_require_pkce_for_public {
        policy.dcr_require_pkce_for_public = value;
    }
    if let Some(value) = patch.dcr_require_pkce_for_confidential {
        policy.dcr_require_pkce_for_confidential = value;
    }
    if let Some(value) = patch.dcr_require_sender_constrained {
        policy.dcr_require_sender_constrained = value;
    }
    if let Some(value) = patch.dcr_allowed_sender_methods.as_ref() {
        policy.dcr_allowed_sender_methods = normalize_lower_list(value);
    }

    if let Some(value) = patch.ssa_jwt_pem.as_deref() {
        policy.ssa_jwt_pem = normalize_optional_text(Some(value));
    }
    if let Some(value) = patch.ssa_expected_iss.as_deref() {
        policy.ssa_expected_iss = normalize_optional_text(Some(value));
    }
    if let Some(value) = patch.ssa_expected_aud.as_deref() {
        policy.ssa_expected_aud = normalize_optional_text(Some(value));
    }
    if let Some(value) = patch.ssa_leeway_seconds {
        policy.ssa_leeway_seconds = value;
    }
}
