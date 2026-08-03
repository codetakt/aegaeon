use axum::{http::StatusCode, response::Response};

use crate::web::oauth_errors::json_error_with_iss;

pub(super) fn federation_error_response(
    status: StatusCode,
    code: &'static str,
    description: &'static str,
    issuer: &str,
) -> Response {
    json_error_with_iss(status, code, Some(description), issuer)
}

pub(super) fn unsupported_federation_query_parameter_response(
    parameter: &str,
    issuer: &str,
) -> Response {
    let description = format!("unsupported federation query parameter '{parameter}'");
    json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "unsupported_parameter",
        Some(description.as_str()),
        issuer,
    )
}
