//! Common metadata checks and contextual subject identity binding.
use super::FederationError;
use serde_json::Value;

mod registration;
pub(crate) use registration::validate_complete_op_registration;

const ENDPOINTS: [&str; 7] = [
    "federation_fetch_endpoint",
    "federation_list_endpoint",
    "federation_resolve_endpoint",
    "federation_trust_mark_status_endpoint",
    "federation_trust_mark_list_endpoint",
    "federation_trust_mark_endpoint",
    "federation_historical_keys_endpoint",
];

fn invalid(entity_type: &str, field: &str) -> FederationError {
    FederationError::Validation(format!("invalid {entity_type} metadata field {field}"))
}

fn validate_url<'a>(
    entity_type: &str,
    field: &str,
    value: &'a Value,
) -> Result<&'a str, FederationError> {
    let uri = value.as_str().ok_or_else(|| invalid(entity_type, field))?;
    // Local lexical policy avoids URL-parser normalization. Admission does not
    // authorize an outbound request or change the supplied string.
    if uri
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        || url::Url::parse(uri).is_err()
    {
        return Err(invalid(entity_type, field));
    }
    Ok(uri)
}

/// Check original or derived metadata without interpreting statement position.
/// Unknown members retain their values, including nested nulls. This does not
/// implement complete imported protocol schemas or outbound URL authorization.
pub(super) fn validate(entity_type: &str, value: &Value) -> Result<(), FederationError> {
    let parameters = value
        .as_object()
        .ok_or_else(|| invalid(entity_type, "object"))?;
    if entity_type == "federation_entity" {
        for field in ["jwks", "jwks_uri", "signed_jwks_uri"] {
            if parameters.contains_key(field) {
                return Err(invalid(entity_type, field));
            }
        }
        for field in ENDPOINTS {
            if let Some(value) = parameters.get(field) {
                let endpoint = value.as_str().ok_or_else(|| invalid(entity_type, field))?;
                super::profile::validate_endpoint(endpoint)
                    .map_err(|_| invalid(entity_type, field))?;
            }
        }
        let field = "endpoint_auth_signing_alg_values_supported";
        if let Some(value) = parameters.get(field) {
            let algorithms = value
                .as_array()
                .ok_or_else(|| invalid(entity_type, field))?;
            if algorithms
                .iter()
                .any(|algorithm| algorithm.as_str().is_none_or(|name| name == "none"))
            {
                return Err(invalid(entity_type, field));
            }
        }
    }
    for (field, value) in parameters {
        if value.is_null() {
            return Err(invalid(entity_type, field));
        }
        match field.as_str() {
            "organization_name" | "display_name" | "description" => {
                if !value.is_string() {
                    return Err(invalid(entity_type, field));
                }
            }
            "keywords" | "contacts" => {
                let items = value
                    .as_array()
                    .ok_or_else(|| invalid(entity_type, field))?;
                if items.is_empty() || items.iter().any(|item| !item.is_string()) {
                    return Err(invalid(entity_type, field));
                }
            }
            "logo_uri" | "policy_uri" | "information_uri" | "organization_uri" => {
                validate_url(entity_type, field, value)?;
            }
            _ => {}
        }
    }
    crate::oidc::capabilities::validate_supplied(entity_type, parameters)
        .map_err(|field| invalid(entity_type, field))?;
    registration::validate_supplied(entity_type, parameters)
}

/// Bind supplied OP/AS identity to the statement subject. Partial metadata may
/// omit issuer; completeness remains the responsibility of the consuming role.
pub(super) fn validate_for_subject(
    entity_type: &str,
    value: &Value,
    subject: &str,
) -> Result<(), FederationError> {
    validate(entity_type, value)?;
    if matches!(
        entity_type,
        "openid_provider" | "oauth_authorization_server"
    ) {
        if let Some(issuer) = value.get("issuer") {
            if issuer.as_str() != Some(subject) {
                return Err(invalid(entity_type, "issuer"));
            }
        }
    }
    Ok(())
}
