use super::{token_error_response, X_FORWARDED_CLIENT_CERT_HEADER};
use crate::authcode::BearerTokenValidationError;
use crate::middleware::DPOP_HEADER;
use crate::util;
use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::fmt::Display;

pub(super) fn json_error_with_iss(
    status: StatusCode,
    error: &str,
    description: Option<&str>,
    issuer_base: &str,
) -> Response {
    let mut body = json!({ "error": error });
    if let Some(desc) = description {
        body["error_description"] = json!(desc);
    }
    body["iss"] = json!(issuer_base);
    (status, Json(body)).into_response()
}

fn oauth_authenticate_value(scheme: &'static str, error: &str) -> HeaderValue {
    let value = format!("{scheme} realm=\"aegaeon\", error=\"{error}\"");
    HeaderValue::from_str(&value)
        .unwrap_or_else(|_| HeaderValue::from_static("Bearer realm=\"aegaeon\""))
}

pub(super) fn apply_oauth_authenticate_header(
    response: &mut Response,
    scheme: &'static str,
    error: &str,
) {
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        oauth_authenticate_value(scheme, error),
    );
}

pub(super) fn bearer_validation_error_response(
    issuer_base: &str,
    challenge_scheme: &'static str,
    err: &BearerTokenValidationError,
) -> Response {
    if err.is_internal() {
        tracing::error!(target: "oauth", error = %err, "bearer token validation failed internally");
        return no_cache_json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some(err.public_description()),
            issuer_base,
        );
    }

    let mut response = json_error_with_iss(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        Some(&err.to_string()),
        issuer_base,
    );
    apply_oauth_authenticate_header(&mut response, challenge_scheme, "invalid_token");
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn bearer_json_error_with_iss(
    status: StatusCode,
    error: &str,
    description: Option<&str>,
    issuer_base: &str,
) -> Response {
    let mut response = json_error_with_iss(status, error, description, issuer_base);
    apply_oauth_authenticate_header(&mut response, "Bearer", error);
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn dpop_invalid_token_response(issuer_base: &str, description: &str) -> Response {
    let mut response = json_error_with_iss(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        Some(description),
        issuer_base,
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("DPoP realm=\"aegaeon\", error=\"invalid_token\""),
    );
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn dpop_backend_unavailable_response(issuer_base: &str) -> Response {
    let mut response = json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("DPoP replay protection backend unavailable"),
        issuer_base,
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("DPoP realm=\"aegaeon\", error=\"temporarily_unavailable\""),
    );
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn registry_state_error_response(
    issuer_base: &str,
    operation: &'static str,
    error: impl Display,
) -> Response {
    tracing::error!(
        target: "oauth",
        operation,
        error = %error,
        "client registry state operation failed internally"
    );
    no_cache_json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some("client registry state unavailable"),
        issuer_base,
    )
}

pub(super) fn authorization_header(
    headers: &HeaderMap,
) -> Result<Option<&str>, util::SingleHeaderError> {
    util::single_header_str(headers, header::AUTHORIZATION.as_str())
}

pub(super) fn dpop_header(headers: &HeaderMap) -> Result<Option<&str>, util::SingleHeaderError> {
    util::single_header_str(headers, DPOP_HEADER)
}

pub(super) fn forwarded_client_cert_header(
    headers: &HeaderMap,
) -> Result<Option<&str>, util::SingleHeaderError> {
    util::single_header_str(headers, X_FORWARDED_CLIENT_CERT_HEADER)
}

pub(super) fn invalid_client_header_error(
    realm: &str,
    header_name: &str,
    err: util::SingleHeaderError,
) -> Response {
    let description = err.description(header_name);
    util::invalid_client_response(realm, &description)
}

pub(super) fn token_header_error(header_name: &str, err: util::SingleHeaderError) -> Response {
    let description = err.description(header_name);
    token_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some(&description),
    )
}

pub(super) fn no_cache_header_error(
    issuer_base: &str,
    header_name: &str,
    err: util::SingleHeaderError,
) -> Response {
    let description = err.description(header_name);
    no_cache_json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some(&description),
        issuer_base,
    )
}

pub(super) fn bearer_header_error(
    issuer_base: &str,
    header_name: &str,
    err: util::SingleHeaderError,
) -> Response {
    let description = err.description(header_name);
    bearer_json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some(&description),
        issuer_base,
    )
}

pub(super) fn dpop_header_error(
    issuer_base: &str,
    header_name: &str,
    err: util::SingleHeaderError,
) -> Response {
    let description = err.description(header_name);
    dpop_invalid_token_response(issuer_base, &description)
}

pub(super) fn no_cache_json_error_with_iss(
    status: StatusCode,
    error: &str,
    description: Option<&str>,
    issuer_base: &str,
) -> Response {
    let mut response = json_error_with_iss(status, error, description, issuer_base);
    util::apply_no_cache_headers(&mut response);
    response
}
