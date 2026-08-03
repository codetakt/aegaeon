use serde_json::Value;

use crate::upstream::{
    UpstreamJitProvisioningCollisionPolicy, UpstreamJitProvisioningInitialStatus,
    UpstreamJitProvisioningPolicy,
};

use super::domain::is_valid_allowlist_domain;

/// # Errors
///
/// Returns an error when `configurationDocument.federation.jitProvisioning`
/// contains invalid types or unsupported values.
pub fn parse_upstream_jit_provisioning_policy(
    federation: Option<&Value>,
) -> Result<Option<UpstreamJitProvisioningPolicy>, String> {
    let Some(federation) = federation else {
        return Ok(None);
    };
    let Some(jit) = federation.get("jitProvisioning") else {
        return Ok(None);
    };
    let jit = jit.as_object().ok_or_else(|| {
        "configurationDocument.federation.jitProvisioning must be an object".to_string()
    })?;
    let enabled = jit.get("enabled").and_then(Value::as_bool).ok_or_else(|| {
        "configurationDocument.federation.jitProvisioning.enabled must be a boolean".to_string()
    })?;
    let require_verified_email = match jit.get("requireVerifiedEmail") {
        None => true,
        Some(value) => value.as_bool().ok_or_else(|| {
            "configurationDocument.federation.jitProvisioning.requireVerifiedEmail must be a boolean"
                .to_string()
        })?,
    };

    let domain_allowlist = match jit.get("domainAllowlist") {
        None => Vec::new(),
        Some(value) => {
            let items = value.as_array().ok_or_else(|| {
                "configurationDocument.federation.jitProvisioning.domainAllowlist must be an array"
                    .to_string()
            })?;
            let mut domains = Vec::with_capacity(items.len());
            for domain in items {
                let normalized = domain
                    .as_str()
                    .map(str::trim)
                    .filter(|candidate| !candidate.is_empty())
                    .map(str::to_ascii_lowercase)
                    .ok_or_else(|| {
                        "configurationDocument.federation.jitProvisioning.domainAllowlist[] must be a non-empty string".to_string()
                    })?;
                if !is_valid_allowlist_domain(&normalized) {
                    return Err(
                        "configurationDocument.federation.jitProvisioning.domainAllowlist[] must contain DNS domains".to_string(),
                    );
                }
                domains.push(normalized);
            }
            domains
        }
    };

    let collision_policy = match jit.get("collisionPolicy") {
        None => UpstreamJitProvisioningCollisionPolicy::RejectExistingEmail,
        Some(value) => UpstreamJitProvisioningCollisionPolicy::parse(
            value
                .as_str()
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .ok_or_else(|| {
                    "configurationDocument.federation.jitProvisioning.collisionPolicy must be a non-empty string".to_string()
                })?,
        )
        .map_err(|_| {
            "configurationDocument.federation.jitProvisioning.collisionPolicy must be one of reject_existing_email or reuse_existing_email".to_string()
        })?,
    };

    let initial_status = match jit.get("initialStatus") {
        None => UpstreamJitProvisioningInitialStatus::Active,
        Some(value) => UpstreamJitProvisioningInitialStatus::parse(
            value
                .as_str()
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .ok_or_else(|| {
                    "configurationDocument.federation.jitProvisioning.initialStatus must be a non-empty string".to_string()
                })?,
        )
        .map_err(|_| {
            "configurationDocument.federation.jitProvisioning.initialStatus must be ACTIVE or BLOCKED".to_string()
        })?,
    };

    Ok(Some(UpstreamJitProvisioningPolicy {
        enabled,
        require_verified_email,
        domain_allowlist,
        collision_policy,
        initial_status,
    }))
}
