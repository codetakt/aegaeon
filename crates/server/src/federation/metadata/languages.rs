//! Known human-facing Federation fields. Unknown and wrong-role names stay opaque.
use super::{invalid, validate_url, FederationError};
use crate::metadata::language_tags;
use serde_json::Value;

#[derive(Clone, Copy)]
enum Kind {
    String,
    Strings,
    Url,
}

fn kind(role: &str, base: &str) -> Option<Kind> {
    match base {
        "organization_name" | "display_name" | "description" => Some(Kind::String),
        "keywords" | "contacts" => Some(Kind::Strings),
        "logo_uri" | "policy_uri" | "information_uri" | "organization_uri" => Some(Kind::Url),
        "service_documentation" | "op_policy_uri" | "op_tos_uri"
            if matches!(role, "openid_provider" | "oauth_authorization_server") =>
        {
            Some(Kind::Url)
        }
        "client_name" if matches!(role, "openid_relying_party" | "oauth_client") => {
            Some(Kind::String)
        }
        "client_uri" | "tos_uri" if matches!(role, "openid_relying_party" | "oauth_client") => {
            Some(Kind::Url)
        }
        "resource_name" if role == "oauth_resource" => Some(Kind::String),
        "resource_documentation" | "resource_policy_uri" | "resource_tos_uri"
            if role == "oauth_resource" =>
        {
            Some(Kind::Url)
        }
        _ => None,
    }
}

fn field_kind(role: &str, field: &str) -> Result<Option<Kind>, FederationError> {
    let Some((base, tag)) = field.split_once('#') else {
        return Ok(kind(role, field));
    };
    let kind = kind(role, base);
    if kind.is_some() && !language_tags::is_valid(tag) {
        return Err(invalid(role, field));
    }
    Ok(kind)
}

/// Policy member names only. Operator objects/operands are not final values.
pub(in crate::federation) fn validate_name(role: &str, field: &str) -> Result<(), FederationError> {
    field_kind(role, field).map(|_| ())
}

pub(super) fn validate_value(
    role: &str,
    field: &str,
    value: &Value,
) -> Result<(), FederationError> {
    match field_kind(role, field)? {
        Some(Kind::String) if !value.is_string() => return Err(invalid(role, field)),
        Some(Kind::Strings) => {
            let items = value.as_array().ok_or_else(|| invalid(role, field))?;
            if items.is_empty() || items.iter().any(|item| !item.is_string()) {
                return Err(invalid(role, field));
            }
        }
        Some(Kind::Url) => {
            validate_url(role, field, value)?;
        }
        _ => {}
    }
    Ok(())
}
