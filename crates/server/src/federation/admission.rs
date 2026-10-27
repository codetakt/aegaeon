//! Contextual admission of individual statements. This does not establish a trust chain.

use super::trust_chain::validate_entity_configuration_link;
use super::{
    validate_entity_statement, verify_entity_configuration, verify_entity_statement,
    EntityStatement, FederationError, JwkSet,
};

pub(crate) fn admit_entity_configuration(
    jws: &str,
    expected_entity_id: &str,
    now: i64,
) -> Result<EntityStatement, FederationError> {
    let statement = verify_entity_configuration(jws)?;
    validate_authority_configuration(&statement, expected_entity_id, now)?;
    Ok(statement)
}

/// Validate a caller-supplied discovery configuration, without authenticating its contents.
pub(in crate::federation) fn validate_authority_configuration(
    statement: &EntityStatement,
    expected_entity_id: &str,
    now: i64,
) -> Result<(), FederationError> {
    validate_entity_configuration_link(statement, expected_entity_id)?;
    validate_entity_statement(statement, now)
}

/// `issuer_jwks` may be superior-endorsed keys. Do not replace it with discovery keys.
pub(in crate::federation) fn admit_subordinate_statement(
    jws: &str,
    expected_issuer: &str,
    expected_subject: &str,
    issuer_jwks: &JwkSet,
    now: i64,
) -> Result<EntityStatement, FederationError> {
    let statement = verify_entity_statement(jws, issuer_jwks)?;
    if statement.is_self_signed()
        || statement.iss != expected_issuer
        || statement.sub != expected_subject
    {
        return Err(FederationError::Validation(
            "subordinate statement does not match requested issuer and subject".into(),
        ));
    }
    validate_entity_statement(&statement, now)?;
    Ok(statement)
}
