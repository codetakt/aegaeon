use serde_json::Value;

use crate::upstream::{
    UpstreamAttributeMapping, UpstreamAttributeMappingRule, UpstreamAttributeMappingTarget,
};

/// # Errors
///
/// Returns an error when `configurationDocument.federation.attributeMapping`
/// is not an array of valid mapping objects.
pub fn parse_upstream_attribute_mappings(
    federation: Option<&Value>,
) -> Result<Vec<UpstreamAttributeMapping>, String> {
    let Some(federation) = federation else {
        return Ok(Vec::new());
    };
    let Some(attribute_mapping) = federation.get("attributeMapping") else {
        return Ok(Vec::new());
    };
    let mappings = attribute_mapping.as_array().ok_or_else(|| {
        "configurationDocument.federation.attributeMapping must be an array".to_string()
    })?;

    let mut parsed = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        let mapping = mapping.as_object().ok_or_else(|| {
            "configurationDocument.federation.attributeMapping entries must be objects".to_string()
        })?;

        let from = mapping
            .get("from")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "configurationDocument.federation.attributeMapping[].from is required".to_string()
            })?;
        let target = mapping
            .get("to")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "configurationDocument.federation.attributeMapping[].to is required".to_string()
            })?;
        let rule = UpstreamAttributeMappingRule::parse(
            mapping
                .get("rule")
                .and_then(|value| value.as_str())
                .map(str::trim),
        )?;

        parsed.push(UpstreamAttributeMapping {
            from: from.to_string(),
            target: UpstreamAttributeMappingTarget::parse(target)?,
            rule,
        });
    }

    Ok(parsed)
}
