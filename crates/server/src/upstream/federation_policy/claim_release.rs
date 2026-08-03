use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::BuildHasher;

use crate::upstream::{
    DownstreamClaimSurface, UpstreamAttributeMapping, UpstreamAttributeMappingTarget,
    UpstreamClaimReleasePolicy,
};

fn managed_custom_claim_targets(
    attribute_mappings: &[UpstreamAttributeMapping],
) -> BTreeSet<String> {
    attribute_mappings
        .iter()
        .filter_map(|mapping| match &mapping.target {
            UpstreamAttributeMappingTarget::Custom(target) => Some(target.clone()),
            _ => None,
        })
        .collect()
}

/// # Errors
///
/// Returns an error when `configurationDocument.federation.claimRelease`
/// references unknown claims or invalid surfaces.
pub fn parse_upstream_claim_release_policy(
    federation: Option<&Value>,
    attribute_mappings: &[UpstreamAttributeMapping],
) -> Result<Option<UpstreamClaimReleasePolicy>, String> {
    let managed_custom_claims = managed_custom_claim_targets(attribute_mappings);
    let Some(federation) = federation else {
        return if managed_custom_claims.is_empty() {
            Ok(None)
        } else {
            Ok(Some(UpstreamClaimReleasePolicy {
                managed_custom_claims: managed_custom_claims.into_iter().collect(),
                ..Default::default()
            }))
        };
    };

    let Some(claim_release) = federation.get("claimRelease") else {
        return if managed_custom_claims.is_empty() {
            Ok(None)
        } else {
            Ok(Some(UpstreamClaimReleasePolicy {
                managed_custom_claims: managed_custom_claims.into_iter().collect(),
                ..Default::default()
            }))
        };
    };

    let rows = claim_release.as_array().ok_or_else(|| {
        "configurationDocument.federation.claimRelease must be an array".to_string()
    })?;
    if managed_custom_claims.is_empty() && rows.is_empty() {
        return Ok(None);
    }

    let mut surfaces_by_claim: BTreeMap<String, BTreeSet<DownstreamClaimSurface>> = BTreeMap::new();
    for row in rows {
        let row = row.as_object().ok_or_else(|| {
            "configurationDocument.federation.claimRelease entries must be objects".to_string()
        })?;
        let claim = row
            .get("claim")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "configurationDocument.federation.claimRelease[].claim is required".to_string()
            })?;
        if !managed_custom_claims.contains(claim) {
            return Err(
                "configurationDocument.federation.claimRelease[].claim must reference a custom claim target managed by attributeMapping".to_string(),
            );
        }

        let surfaces = row
            .get("surfaces")
            .and_then(|value| value.as_array())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "configurationDocument.federation.claimRelease[].surfaces must be a non-empty array"
                    .to_string()
            })?;
        let entry = surfaces_by_claim.entry(claim.to_string()).or_default();
        for surface in surfaces {
            let surface = surface
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    "configurationDocument.federation.claimRelease[].surfaces[] must be id_token or userinfo".to_string()
                })?;
            entry.insert(DownstreamClaimSurface::parse(surface)?);
        }
    }

    Ok(Some(UpstreamClaimReleasePolicy {
        managed_custom_claims: managed_custom_claims.into_iter().collect(),
        id_token_custom_claims: surfaces_by_claim
            .iter()
            .filter_map(|(claim, surfaces)| {
                surfaces
                    .contains(&DownstreamClaimSurface::IdToken)
                    .then_some(claim.clone())
            })
            .collect(),
        userinfo_custom_claims: surfaces_by_claim
            .iter()
            .filter_map(|(claim, surfaces)| {
                surfaces
                    .contains(&DownstreamClaimSurface::Userinfo)
                    .then_some(claim.clone())
            })
            .collect(),
    }))
}

#[must_use]
pub fn filter_downstream_custom_claims(
    custom_claims: &HashMap<String, Value, impl BuildHasher>,
    claim_release_policy: Option<&UpstreamClaimReleasePolicy>,
    surface: DownstreamClaimSurface,
) -> HashMap<String, Value> {
    let Some(claim_release_policy) = claim_release_policy else {
        return custom_claims
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
    };

    custom_claims
        .iter()
        .filter_map(|(key, value)| {
            if claim_release_policy.manages_custom_claim(key)
                && !claim_release_policy.allows_custom_claim(key, surface)
            {
                None
            } else {
                Some((key.clone(), value.clone()))
            }
        })
        .collect()
}
