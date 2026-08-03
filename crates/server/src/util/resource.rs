use super::deserialize_json_without_duplicate_object_keys;
use serde_json::Value;
use url::Url;

/// Parse and validate `authorization_details`.
///
/// # Errors
///
/// Returns an error when the payload is not valid JSON, is not an array of
/// objects, or references unsupported authorization detail types.
pub fn parse_authorization_details(raw: &str, supported_types: &[String]) -> Result<Value, String> {
    let value = deserialize_json_without_duplicate_object_keys::<Value>(raw.as_bytes())
        .map_err(|_| "authorization_details must be a JSON array of objects".to_string())?;
    validate_authorization_details(value, supported_types)
}

/// Validate a parsed `authorization_details` value.
///
/// # Errors
///
/// Returns an error when the value is not a JSON array of objects or when any
/// entry references an unsupported authorization detail type.
pub fn validate_authorization_details(
    value: Value,
    supported_types: &[String],
) -> Result<Value, String> {
    if supported_types.is_empty() {
        return Err("authorization_details are not supported by this server".to_string());
    }

    let array = value
        .as_array()
        .ok_or_else(|| "authorization_details must be a JSON array".to_string())?;

    for (idx, entry) in array.iter().enumerate() {
        let obj = entry
            .as_object()
            .ok_or_else(|| format!("authorization_details[{idx}] must be an object"))?;
        let detail_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("authorization_details[{idx}] must include a non-empty type"))?;
        if !supported_types
            .iter()
            .any(|supported| supported == detail_type)
        {
            return Err(format!(
                "authorization_details type not supported: {detail_type}"
            ));
        }
    }

    Ok(value)
}

/// Validate an RFC 8707 `resource` parameter value.
///
/// - MUST be an absolute URI (RFC 3986 §4.3)
/// - MUST NOT include a fragment component
///
/// # Errors
///
/// Returns an error when the resource is empty, is not an absolute URI, or
/// includes a fragment component.
pub fn validate_resource_indicator(resource: &str) -> Result<String, String> {
    let trimmed = resource.trim();
    if trimmed.is_empty() {
        return Err("resource parameter must not be empty".to_string());
    }
    let parsed = Url::parse(trimmed).map_err(|_| "resource must be an absolute URI".to_string())?;
    if parsed.fragment().is_some() {
        return Err("resource must not include a fragment component".to_string());
    }
    Ok(trimmed.to_string())
}

/// Parse at most one RFC 8707 `resource` value from repeated parameters.
///
/// # Errors
///
/// Returns an error when more than one `resource` value is provided or when the
/// single value fails `validate_resource_indicator`.
pub fn parse_single_resource_indicator(values: &[String]) -> Result<Option<String>, String> {
    match values.len() {
        0 => Ok(None),
        1 => Ok(Some(validate_resource_indicator(&values[0])?)),
        _ => Err("multiple resource parameters are not supported".to_string()),
    }
}
