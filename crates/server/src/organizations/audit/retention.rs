//! Lifetime event bound for the bounded production mutation paths.
//! Native fixture writers and arbitrary/imported database rows are not premises.
use crate::organizations::{commands::capacity, invitations, operators, support, AuthorityError};

const CONFIGURATION_EVENTS: i64 = operators::mutations::MAX_CONFIGURATION_RECEIPTS
    + operators::MAX_OPERATORS as i64
    + operators::mutations::clients::MAX_CLIENTS as i64
    + operators::mutations::targets::MAX_TARGETS as i64
    + 4;
const INVITATION_EVENTS: i64 = invitations::MAX_INVITATIONS
    * (1 + 3
        + invitations::MAX_DELIVERIES
        + 1
        + invitations::MAX_CHALLENGES * (1 + invitations::MAX_DELIVERIES + 1));
const IDENTITY_EVENTS: i64 = invitations::enrollment::MAX_REQUESTS_PER_ENVIRONMENT
    * (1 + invitations::MAX_DELIVERIES + 1 + 1);

// Every new ACK consumes at least one previously pending event; replay consumes
// no additional receipt. Thus this also supports one ACK per lifetime event.
pub(crate) const MAX_EVENTS: i64 = capacity::MAX_OPERATOR_RECEIPTS
    + 2 * capacity::MAX_ORGANIZATIONS
    + capacity::MAX_MEMBER_RECEIPTS
    + 2 * capacity::MAX_MEMBERS
    + CONFIGURATION_EVENTS
    + INVITATION_EVENTS
    + IDENTITY_EVENTS
    + 2 * support::MAX_GRANTS;

pub(crate) const MAX_DATA_BYTES: usize = 28 * 1024;
const MAX_DEPTH: usize = 16;

pub(crate) fn validate_data(data: &serde_json::Value) -> Result<(), AuthorityError> {
    if !data.is_object()
        || !integer_json(data, 0)
        || serde_json::to_vec(data)
            .map_err(|_| AuthorityError::Invalid)?
            .len()
            > MAX_DATA_BYTES
    {
        return Err(AuthorityError::Exhausted);
    }
    Ok(())
}

fn integer_json(value: &serde_json::Value, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    match value {
        serde_json::Value::Number(number) => number.is_i64() || number.is_u64(),
        serde_json::Value::Array(values) => values.iter().all(|v| integer_json(v, depth + 1)),
        serde_json::Value::Object(values) => values.values().all(|v| integer_json(v, depth + 1)),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_audit_data_byte_boundary_and_nested_input_are_bounded() {
        let overhead = serde_json::to_vec(&serde_json::json!({"value":""}))
            .unwrap()
            .len();
        let exact = serde_json::json!({"value":"x".repeat(MAX_DATA_BYTES - overhead)});
        assert!(validate_data(&exact).is_ok());
        let oversized = serde_json::json!({"value":"x".repeat(MAX_DATA_BYTES - overhead + 1)});
        assert_eq!(validate_data(&oversized), Err(AuthorityError::Exhausted));
        let mut nested = serde_json::json!(null);
        for _ in 0..=MAX_DEPTH {
            nested = serde_json::json!({"value":nested});
        }
        assert_eq!(validate_data(&nested), Err(AuthorityError::Exhausted));
    }

    #[test]
    fn organization_audit_data_rejects_postgres_numeric_expansion_and_nonobjects() {
        for value in [
            serde_json::json!({"value":1e200}),
            serde_json::json!({"value":1.5}),
            serde_json::json!([]),
        ] {
            assert_eq!(validate_data(&value), Err(AuthorityError::Exhausted));
        }
        assert!(validate_data(&serde_json::json!({"signed":i64::MIN,"unsigned":u64::MAX})).is_ok());
    }
}
