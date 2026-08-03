mod base;
mod dcr_ssa;
mod downgrade;
mod federation;
mod jwks;
mod jwt;
mod oidc_mtls;
mod runtime;

use crate::management::types::{PolicyDocument, PolicyPatchRequest};

#[cfg(test)]
pub(super) use downgrade::detect_security_downgrade;
pub(super) use downgrade::{
    require_security_downgrade_authorization, SecurityDowngradeAuthorization,
};

pub(super) fn apply_policy_patch(
    mut policy: PolicyDocument,
    patch: &PolicyPatchRequest,
) -> PolicyDocument {
    base::apply_base_policy_patch(&mut policy, patch);
    jwks::apply_jwks_policy_patch(&mut policy, patch);
    jwt::apply_jwt_policy_patch(&mut policy, patch);
    dcr_ssa::apply_dcr_ssa_policy_patch(&mut policy, patch);
    oidc_mtls::apply_oidc_mtls_policy_patch(&mut policy, patch);
    federation::apply_federation_policy_patch(&mut policy, patch);
    runtime::apply_runtime_policy_patch(&mut policy, patch);
    policy
}
