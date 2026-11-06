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
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
    }
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

/// Preserve the failure class and a safe correlation point at every SQL boundary.
/// Never log database error text: it can contain SQL parameters and credentials.
#[track_caller]
pub(in crate::web::management) fn management_database_error(
    request_id: &str,
    error: &sqlx::Error,
    message: &str,
) -> Response {
    let unavailable =
        crate::db::is_temporarily_unavailable(error) || matches!(error, sqlx::Error::PoolClosed);
    let sqlstate = error.as_database_error().and_then(|error| error.code());
    let site = std::panic::Location::caller();
    tracing::error!(target: "management_database", request_id,
        source_file = site.file(), source_line = site.line(),
        sqlstate = sqlstate.as_deref().unwrap_or("none"), unavailable,
        "management database operation failed");
    if unavailable {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Management database unavailable",
            None,
            Some(request_id),
        )
    } else {
        management_internal_error(request_id, message)
    }
}

/// Session operations record diagnostics once at the store boundary. Do not log
/// again here, or a single failed operation would consume two outage events.
pub(in crate::web::management) fn management_session_error(
    request_id: &str,
    error: &super::state::SessionStoreError,
) -> Response {
    if error.is_unavailable() {
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "Session store unavailable",
            None,
            Some(request_id),
        )
    } else {
        management_internal_error(request_id, "Session store operation failed")
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::management::state::SessionStoreError;

    #[tokio::test]
    async fn management_session_failures_preserve_class_and_envelope() {
        for (error, status) in [
            (
                SessionStoreError::Database(sqlx::Error::PoolClosed),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                SessionStoreError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                SessionStoreError::Database(sqlx::Error::ColumnNotFound("private-column".into())),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                SessionStoreError::InvalidState,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let response = management_session_error("outage-request", &error);
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["x-request-id"], "outage-request");
            assert!(response.headers()["cache-control"]
                .to_str()
                .unwrap()
                .contains("no-store"));
            assert_eq!(
                response
                    .headers()
                    .get("retry-after")
                    .map(|v| v.to_str().unwrap()),
                (status == StatusCode::SERVICE_UNAVAILABLE).then_some("1")
            );
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["requestId"], "outage-request");
            assert_eq!(
                json["errorCode"],
                if status == StatusCode::SERVICE_UNAVAILABLE {
                    "temporarily_unavailable"
                } else {
                    "internal_error"
                }
            );
            assert!(!String::from_utf8_lossy(&body).contains("private-column"));
        }
    }
}
