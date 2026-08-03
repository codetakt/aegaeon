use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

use super::super::http_errors::{error_response, invalid_field_details};

pub(in crate::web::management) fn parse_uuid_param(
    value: &str,
    field: &str,
    request_id: &str,
) -> Result<Uuid, Response> {
    Uuid::parse_str(value).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid UUID parameter",
            Some(invalid_field_details(field)),
            Some(request_id),
        )
    })
}
