use axum::response::Response;

use crate::management::types::PolicyDocument;

use super::super::super::{invalid_numeric_field_response, MAX_SQL_INTEGER_SECONDS};

mod fields;

pub(super) fn validate_sql_integer_bounds(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    for (field, value) in fields::sql_integer_fields(policy) {
        if value > MAX_SQL_INTEGER_SECONDS {
            return Err(invalid_numeric_field_response(field, request_id));
        }
    }

    Ok(())
}
