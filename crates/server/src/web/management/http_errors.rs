use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use sqlx::{postgres::PgRow, Postgres, Row};

use crate::management::types::ErrorResponse;
use crate::middleware::tls::TransportRejectionKind;
use crate::util;

pub(super) fn error_response(
    status: StatusCode,
    error_code: &str,
    message: &str,
    details: Option<serde_json::Value>,
    request_id: Option<&str>,
) -> Response {
    let body = ErrorResponse {
        error_code: error_code.to_string(),
        message: message.to_string(),
        details,
        request_id: request_id.map(ToString::to_string),
    };
    let mut response = (status, Json(body)).into_response();
    crate::util::apply_no_cache_headers(&mut response);
    if let Some(request_id) = request_id {
        insert_request_id_header(response.headers_mut(), request_id);
    }
    response
}

pub(super) fn invalid_field_details(field_name: &str) -> serde_json::Value {
    serde_json::json!({ "field": field_name })
}

pub(super) fn forbidden(error_code: &str, message: &str, request_id: &str) -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        error_code,
        message,
        None,
        Some(request_id),
    )
}

pub(super) fn insert_request_id_header(headers: &mut HeaderMap, request_id: &str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert("x-request-id", value);
    }
}

pub(super) fn management_internal_error(request_id: &str, message: &str) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        message,
        None,
        Some(request_id),
    )
}

pub(super) fn management_transport_rejection(
    kind: TransportRejectionKind,
    request_id: &str,
) -> Response {
    let (status, error_code, message) = match kind {
        TransportRejectionKind::UntrustedProxy | TransportRejectionKind::MissingRemoteAddr => (
            StatusCode::FORBIDDEN,
            "access_denied",
            "request did not originate from a trusted proxy",
        ),
        TransportRejectionKind::MissingForwardedHeader => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "forwarded header required to assert HTTPS transport",
        ),
        TransportRejectionKind::MalformedForwardedHeader => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "forwarded header was malformed",
        ),
        TransportRejectionKind::InsecureProto => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "insecure transport: HTTPS required",
        ),
        TransportRejectionKind::MtlsClientCertMissing => (
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client certificate required for mTLS-bound tokens",
        ),
    };

    error_response(status, error_code, message, None, Some(request_id))
}

fn invalid_management_header_response(
    header_name: &str,
    err: util::SingleHeaderError,
    request_id: &str,
) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        &err.description(header_name),
        None,
        Some(request_id),
    )
}

pub(super) fn management_single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    display_name: &str,
    request_id: &str,
) -> Result<Option<&'a str>, Response> {
    util::single_header_str(headers, name)
        .map_err(|err| invalid_management_header_response(display_name, err, request_id))
}

pub(super) fn required_row_value<'r, T>(
    row: &'r PgRow,
    column: &str,
    request_id: &str,
    message: &str,
) -> Result<T, Response>
where
    T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    row.try_get(column)
        .map_err(|_| management_internal_error(request_id, message))
}

pub(super) fn management_environment_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Environment not found",
        None,
        Some(request_id),
    )
}

pub(super) fn management_team_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Team not found",
        None,
        Some(request_id),
    )
}

pub(super) fn management_tenant_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Tenant not found",
        None,
        Some(request_id),
    )
}
