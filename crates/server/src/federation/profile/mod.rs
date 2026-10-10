mod claims;
mod urls;

use super::{raw_payload, EntityStatement, FederationError, JwkSet, ResolvedTrustChain};
use serde_json::{Map, Value};

pub(super) use urls::{validate_endpoint, validate_identifier};

fn invalid(field: &'static str) -> FederationError {
    FederationError::Validation(format!("invalid Entity Statement {field}"))
}

/// Project only after the existing structural decoder has admitted these bytes.
fn project_admitted_object(payload: &[u8]) -> Result<Map<String, Value>, FederationError> {
    crate::util::validate_json_without_duplicate_object_keys(payload)
        .map_err(|_| invalid("JSON object"))?;
    serde_json::from_slice(payload).map_err(|_| invalid("JSON object"))
}

pub(super) fn admitted_payload(
    payload: &[u8],
) -> Result<(EntityStatement, Map<String, Value>), FederationError> {
    let statement = raw_payload::parse_entity_statement_payload(payload)?;
    let claims = project_admitted_object(payload)?;
    let projected: EntityStatement = serde_json::from_value(Value::Object(claims.clone()))
        .map_err(|_| invalid("typed projection"))?;
    if serde_json::to_value(&statement)? != serde_json::to_value(projected)? {
        return Err(invalid("typed projection"));
    }
    Ok((statement, claims))
}

pub(super) fn validate_verified_payload(
    payload: &[u8],
) -> Result<EntityStatement, FederationError> {
    let (statement, claims) = admitted_payload(payload)?;
    claims::validate(&claims)?;
    Ok(statement)
}

pub(super) fn validate_typed(statement: &EntityStatement) -> Result<(), FederationError> {
    let Value::Object(claims) = serde_json::to_value(statement)? else {
        return Err(invalid("typed projection"));
    };
    claims::validate(&claims)
}

/// Check original members before the generic JWK material view is constructed.
pub(crate) fn validate_federation_jwks(value: &Value) -> Result<JwkSet, FederationError> {
    let keys = value
        .as_object()
        .and_then(|o| o.get("keys"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("jwks"))?;
    let mut kids = std::collections::HashSet::new();
    for key in keys {
        let kid = key
            .as_object()
            .and_then(|o| o.get("kid"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("jwks kid"))?;
        if !kids.insert(kid) {
            return Err(invalid("jwks kid"));
        }
    }
    let jwks = JwkSet::from_value(value.clone()).map_err(|_| invalid("jwks material"))?;
    if jwks.signature_keys().next().is_none() {
        return Err(invalid("jwks signing keys"));
    }
    Ok(jwks)
}

pub(super) fn validate_superior(statement: &EntityStatement) -> Result<(), FederationError> {
    let metadata = statement
        .metadata
        .as_ref()
        .and_then(|m| m.get("federation_entity"))
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("superior metadata"))?;
    for field in ["federation_fetch_endpoint", "federation_list_endpoint"] {
        let endpoint = metadata
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("superior endpoints"))?;
        validate_endpoint(endpoint)?;
    }
    Ok(())
}

/// Context gate for an already verified chain; no new signature verification or retrieval.
pub(crate) fn validate_oidc_upstream_chain(
    chain: &ResolvedTrustChain,
) -> Result<(), FederationError> {
    if chain.chain_jwts.is_empty() {
        return Err(invalid("OIDC chain"));
    }
    for (index, jwt) in chain.chain_jwts.iter().enumerate() {
        let parsed = super::Jws::from_compact(jwt)?;
        let (_, claims) = admitted_payload(&parsed.payload)?;
        if claims.contains_key("aud") || claims.contains_key("trust_anchor") {
            return Err(invalid("ordinary OIDC claims"));
        }
        if index == 0
            && !claims
                .get("metadata")
                .and_then(|m| m.get("openid_provider"))
                .is_some_and(Value::is_object)
        {
            return Err(invalid("signed openid_provider metadata"));
        }
    }
    Ok(())
}

pub(super) fn validate_trust_marks(value: &Value) -> Result<(), FederationError> {
    let marks = value.as_array().ok_or_else(|| invalid("trust_marks"))?;
    for mark in marks {
        let mark = mark.as_object().ok_or_else(|| invalid("trust_marks"))?;
        let mark_type = mark
            .get("trust_mark_type")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("trust_marks type"))?;
        let jwt = mark
            .get("trust_mark")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("trust_marks JWT"))?;
        let parsed = super::Jws::from_compact(jwt).map_err(|_| invalid("trust_marks JWT"))?;
        if parsed.signature.is_empty()
            || aegaeon_jose::jws::JwsAlgorithm::try_from(parsed.header.alg.as_str()).is_err()
        {
            return Err(invalid("trust_marks JWT"));
        }
        let typed = raw_payload::parse_trust_mark_claims_payload(&parsed.payload)
            .map_err(|_| invalid("trust_marks JWT"))?;
        let claims = project_admitted_object(&parsed.payload)?;
        if claims.get("trust_mark_type").and_then(Value::as_str) != Some(mark_type)
            || typed.id != mark_type
        {
            return Err(invalid("trust_marks type"));
        }
    }
    Ok(())
}
