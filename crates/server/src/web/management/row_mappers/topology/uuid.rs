use axum::response::Response;
use uuid::Uuid;

use super::super::super::management_internal_error;

pub(in crate::web::management) fn parse_optional_stored_uuid(
    value: Option<&str>,
    field_name: &str,
    request_id: &str,
) -> Result<Option<Uuid>, Response> {
    match value {
        Some(raw) => Uuid::parse_str(raw).map(Some).map_err(|_| {
            management_internal_error(request_id, &format!("Failed to parse stored {field_name}"))
        }),
        None => Ok(None),
    }
}
