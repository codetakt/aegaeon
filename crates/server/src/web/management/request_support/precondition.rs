use axum::{http::HeaderMap, response::Response};
use uuid::Uuid;

use super::super::{management_single_header, parse_uuid_param};

pub(in crate::web::management) const BASE_CONFIGURATION_VERSION_HEADER: &str =
    "aegaeon-base-configuration-version-id";

pub(in crate::web::management) fn base_configuration_version_id_from_header(
    headers: &HeaderMap,
    request_id: &str,
) -> Result<Uuid, Response> {
    let value = management_single_header(
        headers,
        BASE_CONFIGURATION_VERSION_HEADER,
        BASE_CONFIGURATION_VERSION_HEADER,
        request_id,
    )?
    .ok_or_else(|| {
        super::super::error_response(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing base configuration version precondition header",
            Some(super::super::invalid_field_details(
                BASE_CONFIGURATION_VERSION_HEADER,
            )),
            Some(request_id),
        )
    })?;
    parse_uuid_param(value, BASE_CONFIGURATION_VERSION_HEADER, request_id)
}
