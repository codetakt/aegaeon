use crate::web::management::{error_response, invalid_field_details};
use axum::{http::StatusCode, response::Response};
use url::Url;

pub(super) fn validate_https_url_field(
    field_name: &str,
    value: &str,
    request_id: &str,
) -> Result<Url, Response> {
    let parsed = Url::parse(value).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Federation URL must be a valid https URL",
            Some(invalid_field_details(field_name)),
            Some(request_id),
        )
    })?;
    if parsed.scheme() != "https" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Federation URL must use https",
            Some(invalid_field_details(field_name)),
            Some(request_id),
        ));
    }
    if parsed.host_str().is_none() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Federation URL must include a host",
            Some(invalid_field_details(field_name)),
            Some(request_id),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Federation URL must not include a query or fragment",
            Some(invalid_field_details(field_name)),
            Some(request_id),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Federation URL must not include userinfo",
            Some(invalid_field_details(field_name)),
            Some(request_id),
        ));
    }
    if crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Federation URL must not target non-routable hosts",
            Some(invalid_field_details(field_name)),
            Some(request_id),
        ));
    }
    Ok(parsed)
}
