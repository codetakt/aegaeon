use super::super::{EntityStatement, FederationError};

pub(in crate::federation) fn validate_entity_configuration_link(
    stmt: &EntityStatement,
    expected_entity_id: &str,
) -> Result<(), FederationError> {
    if stmt.iss != expected_entity_id || stmt.sub != expected_entity_id {
        return Err(FederationError::Validation(
            "entity configuration does not match expected entity_id".into(),
        ));
    }
    if !stmt.is_self_signed() {
        return Err(FederationError::Validation(
            "entity configuration must be self-signed".into(),
        ));
    }
    Ok(())
}

pub(in crate::federation) fn validate_subordinate_statement_link(
    sub_stmt: &EntityStatement,
    superior_config: &EntityStatement,
    expected_subject: &str,
) -> Result<(), FederationError> {
    if sub_stmt.is_self_signed() {
        return Err(FederationError::Validation(
            "subordinate statement must not be self-signed".into(),
        ));
    }
    if !superior_config.is_self_signed() {
        return Err(FederationError::Validation(
            "superior entity configuration must be self-signed".into(),
        ));
    }
    if sub_stmt.sub != expected_subject {
        return Err(FederationError::Validation(
            "subordinate statement subject breaks chain continuity".into(),
        ));
    }
    if sub_stmt.iss != superior_config.iss {
        return Err(FederationError::Validation(
            "subordinate statement issuer does not match superior".into(),
        ));
    }
    Ok(())
}
