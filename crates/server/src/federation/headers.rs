use aegaeon_jose::jws::JwsHeader;

use super::FederationError;

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
