use serde_json::{Map, Value};
use std::collections::HashSet;

use crate::oidc::IdToken;
use crate::upstream::{
    AppliedUpstreamAttributeMappings, UpstreamAttributeMapping, UpstreamAttributeMappingRule,
    UpstreamAttributeMappingTarget,
};

fn resolve_upstream_attribute_source(id_token: &IdToken, source: &str) -> Option<Value> {
    match source.trim() {
        "sub" => Some(Value::String(id_token.claims.sub.clone())),
        "iss" => Some(Value::String(id_token.claims.iss.clone())),
        "acr" => id_token
            .claims
            .acr
            .as_ref()
            .map(|value| Value::String(value.clone())),
        "sid" => id_token
            .claims
            .sid
            .as_ref()
            .map(|value| Value::String(value.clone())),
        "auth_time" => id_token
            .claims
            .auth_time
            .map(|value| serde_json::json!(value)),
        "amr" => id_token
            .claims
            .amr
            .as_ref()
            .map(|value| serde_json::json!(value)),
        other => id_token.claims.additional_claims.get(other).cloned(),
    }
}

fn lower_attribute_value(value: Value) -> Result<Value, String> {
    match value {
        Value::String(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                Err("lower requires a non-empty string".to_string())
            } else {
                Ok(Value::String(normalized))
            }
        }
        Value::Array(values) => {
            let mut lowered = Vec::with_capacity(values.len());
            for value in values {
                let Value::String(raw) = value else {
                    return Err("lower requires a string or array of strings".to_string());
                };
                let normalized = raw.trim().to_ascii_lowercase();
                if !normalized.is_empty() {
                    lowered.push(Value::String(normalized));
                }
            }
            Ok(Value::Array(lowered))
        }
        _ => Err("lower requires a string or array of strings".to_string()),
    }
}

fn split_group_values(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if trimmed.contains(',') || trimmed.contains(';') {
        trimmed
            .split([',', ';'])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        trimmed
            .split_whitespace()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect()
    }
}

fn map_groups_attribute_value(value: Value) -> Result<Value, String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    let mut push_group = |group: String| {
        let lowered = group.trim().to_ascii_lowercase();
        if !lowered.is_empty() && seen.insert(lowered.clone()) {
            normalized.push(Value::String(lowered));
        }
    };

    match value {
        Value::String(raw) => {
            for group in split_group_values(&raw) {
                push_group(group);
            }
        }
        Value::Array(values) => {
            for value in values {
                let Value::String(raw) = value else {
                    return Err("mapGroups requires a string or array of strings".to_string());
                };
                for group in split_group_values(&raw) {
                    push_group(group);
                }
            }
        }
        _ => return Err("mapGroups requires a string or array of strings".to_string()),
    }

    Ok(Value::Array(normalized))
}

fn apply_upstream_attribute_rule(
    rule: &UpstreamAttributeMappingRule,
    value: Value,
) -> Result<Value, String> {
    match rule {
        UpstreamAttributeMappingRule::Copy => Ok(value),
        UpstreamAttributeMappingRule::Lower => lower_attribute_value(value),
        UpstreamAttributeMappingRule::MapGroups => map_groups_attribute_value(value),
    }
}

fn coerce_attribute_string(value: Value) -> Result<String, String> {
    let Value::String(raw) = value else {
        return Err("mapped value must be a string".to_string());
    };
    let normalized = raw.trim();
    if normalized.is_empty() {
        Err("mapped value must be a non-empty string".to_string())
    } else {
        Ok(normalized.to_string())
    }
}

fn coerce_attribute_bool(value: Value) -> Result<bool, String> {
    match value {
        Value::Bool(value) => Ok(value),
        Value::String(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err("mapped value must be a boolean".to_string()),
        },
        Value::Number(number) => {
            if number.as_i64() == Some(1) {
                Ok(true)
            } else if number.as_i64() == Some(0) {
                Ok(false)
            } else {
                Err("mapped value must be a boolean".to_string())
            }
        }
        _ => Err("mapped value must be a boolean".to_string()),
    }
}

/// # Errors
///
/// Returns an error when an upstream attribute mapping resolves to a value that
/// cannot be coerced into the requested target type.
pub fn project_upstream_attribute_mappings(
    mappings: &[UpstreamAttributeMapping],
    id_token: &IdToken,
) -> Result<AppliedUpstreamAttributeMappings, String> {
    let mut projection = AppliedUpstreamAttributeMappings::default();
    let mut managed_custom_claims = HashSet::new();

    for mapping in mappings {
        let resolved = match resolve_upstream_attribute_source(id_token, &mapping.from) {
            Some(value) => Some(apply_upstream_attribute_rule(&mapping.rule, value).map_err(
                |message| {
                    format!(
                        "failed to apply federation attribute mapping from `{}`: {}",
                        mapping.from, message
                    )
                },
            )?),
            None => None,
        };

        match &mapping.target {
            UpstreamAttributeMappingTarget::Email => {
                projection.email = Some(match resolved {
                    Some(value) => Some(coerce_attribute_string(value).map_err(|message| {
                        format!(
                            "failed to map upstream claim `{}` to email: {}",
                            mapping.from, message
                        )
                    })?),
                    None => None,
                });
            }
            UpstreamAttributeMappingTarget::EmailVerified => {
                projection.email_verified = Some(match resolved {
                    Some(value) => coerce_attribute_bool(value).map_err(|message| {
                        format!(
                            "failed to map upstream claim `{}` to email_verified: {}",
                            mapping.from, message
                        )
                    })?,
                    None => false,
                });
            }
            UpstreamAttributeMappingTarget::DisplayName => {
                projection.display_name = Some(match resolved {
                    Some(value) => Some(coerce_attribute_string(value).map_err(|message| {
                        format!(
                            "failed to map upstream claim `{}` to name: {}",
                            mapping.from, message
                        )
                    })?),
                    None => None,
                });
            }
            UpstreamAttributeMappingTarget::Custom(target) => {
                if managed_custom_claims.insert(target.clone()) {
                    projection.managed_custom_claim_keys.push(target.clone());
                }
                if let Some(value) = resolved {
                    projection.custom_claims.insert(target.clone(), value);
                } else {
                    projection.custom_claims.remove(target);
                }
            }
        }
    }

    Ok(projection)
}

pub fn merge_upstream_custom_claims(
    existing_custom_claims: &Value,
    projection: &AppliedUpstreamAttributeMappings,
) -> Value {
    let mut merged = existing_custom_claims
        .as_object()
        .cloned()
        .unwrap_or_else(Map::new);

    for key in &projection.managed_custom_claim_keys {
        merged.remove(key);
    }
    for (key, value) in &projection.custom_claims {
        merged.insert(key.clone(), value.clone());
    }

    Value::Object(merged)
}
