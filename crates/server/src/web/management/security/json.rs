use axum::{
    body::{self, Body},
    http::{header, HeaderMap, StatusCode},
    response::Response,
};

use crate::util;

use super::super::{error_response, management_single_header, MAX_MANAGEMENT_JSON_BODY_BYTES};

pub(in crate::web::management) fn enforce_json_content_type(
    headers: &HeaderMap,
    request_id: &str,
) -> Result<(), Response> {
    let value = management_single_header(
        headers,
        header::CONTENT_TYPE.as_str(),
        "Content-Type",
        request_id,
    )?
    .map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    });
    match value.as_deref() {
        Some("application/json") => Ok(()),
        _ => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Content-Type must be application/json",
            None,
            Some(request_id),
        )),
    }
}

pub(in crate::web::management) async fn enforce_management_json_body_admission(
    req: axum::http::Request<Body>,
    request_id: &str,
) -> Result<axum::http::Request<Body>, Response> {
    let (parts, body) = req.into_parts();
    let bytes = body::to_bytes(body, MAX_MANAGEMENT_JSON_BODY_BYTES)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "Request body is too large",
                None,
                Some(request_id),
            )
        })?;

    if !bytes.is_empty() {
        validate_management_json_without_duplicate_keys(&bytes).map_err(|err| {
            let (message, reason) = match err {
                util::JsonAdmissionError::DuplicateKey => (
                    "JSON object keys must not be specified multiple times",
                    "duplicate-key",
                ),
                util::JsonAdmissionError::InvalidJson | util::JsonAdmissionError::TrailingBytes => {
                    ("Request body must be valid JSON", "invalid-json")
                }
            };
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                Some(serde_json::json!({ "reason": reason })),
                Some(request_id),
            )
        })?;
    }

    Ok(axum::http::Request::from_parts(parts, Body::from(bytes)))
}

pub(in crate::web::management) async fn enforce_empty_management_delete_body(
    req: axum::http::Request<Body>,
    request_id: &str,
) -> Result<axum::http::Request<Body>, Response> {
    let (parts, body) = req.into_parts();
    let bytes = body::to_bytes(body, 0).await.map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "DELETE requests must not include a body",
            None,
            Some(request_id),
        )
    })?;
    if !bytes.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "DELETE requests must not include a body",
            None,
            Some(request_id),
        ));
    }
    Ok(axum::http::Request::from_parts(parts, Body::empty()))
}

pub(in crate::web::management) fn validate_management_json_without_duplicate_keys(
    bytes: &[u8],
) -> Result<(), util::JsonAdmissionError> {
    util::validate_json_without_duplicate_object_keys(bytes)
}
