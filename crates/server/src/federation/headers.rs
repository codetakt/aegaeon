use aegaeon_jose::jws::JwsHeader;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use super::FederationError;

/// Called after generic JWS admission. Preserve these Federation prohibitions
/// independently of whether generic JOSE accepts unknown header parameters.
pub(super) fn validate_entity_statement_headers(compact: &str) -> Result<(), FederationError> {
    let header = compact
        .split('.')
        .next()
        .ok_or(aegaeon_jose::jws::JwsError::InvalidFormat)?;
    validate_entity_statement_header_bytes(&URL_SAFE_NO_PAD.decode(header)?)
}

pub(super) fn validate_entity_statement_header_bytes(bytes: &[u8]) -> Result<(), FederationError> {
    let invalid =
        || FederationError::Validation("invalid Entity Statement protected headers".into());
    crate::util::validate_json_without_duplicate_object_keys(bytes).map_err(|_| invalid())?;
    let header: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if header.contains_key("trust_chain") || header.contains_key("peer_trust_chain") {
        return Err(FederationError::Validation(
            "Entity Statement must not contain trust chain headers".into(),
        ));
    }
    Ok(())
}

/// Federation JWT purpose and key identification are checked before key selection.
/// Key IDs are opaque strings: preserve case and whitespace for exact matching.
pub(super) fn required_signing_kid<'a>(
    header: &'a JwsHeader,
    expected_typ: &str,
) -> Result<&'a str, FederationError> {
    if header.typ.as_deref() != Some(expected_typ) {
        return Err(FederationError::Validation(format!(
            "Federation JWT typ must be {expected_typ}"
        )));
    }
    header
        .kid
        .as_deref()
        .filter(|kid| !kid.is_empty())
        .ok_or_else(|| FederationError::Validation("Federation JWT requires a nonempty kid".into()))
}
