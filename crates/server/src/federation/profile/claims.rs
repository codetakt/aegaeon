use super::{
    invalid, validate_endpoint, validate_federation_jwks, validate_identifier,
    validate_trust_marks, FederationError,
};
use serde_json::{Map, Value};

const CONFIGURATION_ONLY: [&str; 5] = [
    "authority_hints",
    "trust_anchor_hints",
    "trust_marks",
    "trust_mark_issuers",
    "trust_mark_owners",
];
const SUBORDINATE_ONLY: [&str; 4] = [
    "constraints",
    "metadata_policy",
    "metadata_policy_crit",
    "source_endpoint",
];
const ENDPOINTS: [&str; 7] = [
    "federation_fetch_endpoint",
    "federation_list_endpoint",
    "federation_resolve_endpoint",
    "federation_trust_mark_status_endpoint",
    "federation_trust_mark_list_endpoint",
    "federation_trust_mark_endpoint",
    "federation_historical_keys_endpoint",
];

pub(super) fn validate(claims: &Map<String, Value>) -> Result<(), FederationError> {
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("iss"))?;
    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("sub"))?;
    validate_identifier(iss)?;
    validate_identifier(sub)?;
    let configuration = iss == sub;
    let forbidden: &[&str] = if configuration {
        &SUBORDINATE_ONLY
    } else {
        &CONFIGURATION_ONLY
    };
    if forbidden.iter().any(|name| claims.contains_key(*name)) {
        return Err(invalid("statement-kind claims"));
    }
    if claims.contains_key("crit") || claims.contains_key("metadata_policy_crit") {
        return Err(invalid("unsupported critical claims"));
    }
    validate_federation_jwks(
        claims
            .get("jwks")
            .ok_or(FederationError::MissingField("jwks"))?,
    )?;
    if let Some(value) = claims.get("metadata") {
        validate_metadata(value, configuration)?;
    }
    for field in ["authority_hints", "trust_anchor_hints"] {
        if let Some(value) = claims.get(field) {
            validate_identifiers(value, false)?;
        }
    }
    if let Some(value) = claims.get("trust_marks") {
        validate_trust_marks(value)?;
    }
    if let Some(value) = claims.get("trust_mark_issuers") {
        for issuers in value
            .as_object()
            .ok_or_else(|| invalid("trust_mark_issuers"))?
            .values()
        {
            validate_identifiers(issuers, true)?;
        }
    }
    if let Some(value) = claims.get("trust_mark_owners") {
        for owner in value
            .as_object()
            .ok_or_else(|| invalid("trust_mark_owners"))?
            .values()
        {
            let owner = owner
                .as_object()
                .ok_or_else(|| invalid("trust_mark_owners"))?;
            let sub = owner
                .get("sub")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("trust_mark_owners sub"))?;
            validate_identifier(sub)?;
            validate_federation_jwks(
                owner
                    .get("jwks")
                    .ok_or_else(|| invalid("trust_mark_owners jwks"))?,
            )?;
        }
    }
    for field in ["constraints", "metadata_policy"] {
        if claims.get(field).is_some_and(|value| !value.is_object()) {
            return Err(invalid("subordinate object claims"));
        }
    }
    if let Some(value) = claims.get("constraints") {
        validate_constraints(value)?;
    }
    if let Some(value) = claims.get("source_endpoint") {
        validate_endpoint(value.as_str().ok_or_else(|| invalid("source_endpoint"))?)?;
    }
    Ok(())
}

fn validate_identifiers(value: &Value, empty_allowed: bool) -> Result<(), FederationError> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid("Entity Identifier array"))?;
    if values.is_empty() && !empty_allowed {
        return Err(invalid("empty Entity Identifier array"));
    }
    for value in values {
        validate_identifier(
            value
                .as_str()
                .ok_or_else(|| invalid("Entity Identifier array"))?,
        )?;
    }
    Ok(())
}

fn validate_metadata(value: &Value, configuration: bool) -> Result<(), FederationError> {
    let metadata = value.as_object().ok_or_else(|| invalid("metadata"))?;
    for (entity_type, parameters) in metadata {
        let parameters = parameters
            .as_object()
            .ok_or_else(|| invalid("metadata entity type"))?;
        if parameters.values().any(Value::is_null) {
            return Err(invalid("metadata null parameter"));
        }
        if entity_type == "federation_entity" {
            if !configuration
                && ["federation_fetch_endpoint", "federation_list_endpoint"]
                    .iter()
                    .any(|field| parameters.contains_key(*field))
            {
                return Err(invalid("subordinate discovery endpoints"));
            }
            for field in ENDPOINTS {
                if let Some(value) = parameters.get(field) {
                    validate_endpoint(
                        value
                            .as_str()
                            .ok_or_else(|| invalid("federation endpoint"))?,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_constraints(value: &Value) -> Result<(), FederationError> {
    let object = value.as_object().ok_or_else(|| invalid("constraints"))?;
    if object.get("max_path_length").is_some_and(|value| {
        value
            .as_u64()
            .is_none_or(|number| u32::try_from(number).is_err())
    }) {
        return Err(invalid("max_path_length"));
    }
    for field in ["allowed_entity_types", "allowed_leaf_entity_types"] {
        if let Some(value) = object.get(field) {
            let types = value.as_array().ok_or_else(|| invalid(field))?;
            if types.iter().any(|value| !value.is_string()) {
                return Err(invalid(field));
            }
        }
    }
    let constraints: super::super::Constraints =
        serde_json::from_value(value.clone()).map_err(|_| invalid("constraints"))?;
    constraints.validate()
}
