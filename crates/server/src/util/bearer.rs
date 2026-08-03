use super::apply_no_cache_headers;
use axum::response::{IntoResponse, Response};
use axum::Json;
use http::{header::WWW_AUTHENTICATE, HeaderValue, StatusCode};
use serde_json::json;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum BearerTokenError {
    Missing,
    InvalidScheme,
    MultipleMethods,
}

impl fmt::Display for BearerTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BearerTokenError::Missing => write!(f, "Missing bearer token"),
            BearerTokenError::InvalidScheme => {
                write!(f, "Authorization header must use the Bearer scheme")
            }
            BearerTokenError::MultipleMethods => {
                write!(f, "Bearer token supplied via multiple transport methods")
            }
        }
    }
}

/// Parse an RFC 6750 Authorization header carrying exactly one Bearer token.
///
/// # Errors
///
/// Returns `BearerTokenError` when the header does not use the Bearer scheme,
/// omits the token, or contains extra whitespace-separated material.
pub fn parse_bearer_authorization_header(header: &str) -> Result<&str, BearerTokenError> {
    let mut parts = header.split_whitespace();
    let Some(scheme) = parts.next() else {
        return Err(BearerTokenError::Missing);
    };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(BearerTokenError::InvalidScheme);
    }
    let Some(token) = parts.next() else {
        return Err(BearerTokenError::Missing);
    };
    if parts.next().is_some() {
        return Err(BearerTokenError::InvalidScheme);
    }

    Ok(token)
}

/// Extract a bearer token from at most one transport location as per RFC 6750 §2.
/// Returns an error if no token is present, if the Authorization header scheme
/// is not Bearer, or if more than one transport mechanism is used.
///
/// # Errors
///
/// Returns `BearerTokenError` when the token is missing, uses the wrong scheme,
/// or is supplied through multiple transport mechanisms.
pub fn extract_bearer_token(
    authorization_header: Option<&str>,
    query_token: Option<&str>,
    body_token: Option<&str>,
) -> Result<String, BearerTokenError> {
    let header_token = authorization_header
        .map(parse_bearer_authorization_header)
        .transpose()?
        .map(str::to_owned);
    let query_token = query_token.map(str::to_owned);
    let body_token = body_token.map(str::to_owned);

    let mut tokens = [header_token, query_token, body_token]
        .into_iter()
        .flatten();
    let Some(token) = tokens.next() else {
        return Err(BearerTokenError::Missing);
    };
    if tokens.next().is_some() {
        return Err(BearerTokenError::MultipleMethods);
    }
    Ok(token)
}

/// Create an RFC 6750 compliant error response for invalid bearer tokens.
pub fn bearer_invalid_token_response(description: &str) -> Response {
    let sanitized = description.replace('"', "'");
    let body = json!({
        "error": "invalid_token",
        "error_description": sanitized,
    });
    let mut response = (StatusCode::UNAUTHORIZED, Json(body)).into_response();
    let header_value = format!("Bearer error=\"invalid_token\", error_description=\"{sanitized}\"");
    if let Ok(value) = HeaderValue::from_str(&header_value) {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    } else {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"invalid_token\""),
        );
    }
    apply_no_cache_headers(&mut response);
    response
}

/// Construct an RFC 6749/7009 `invalid_client` HTTP response with WWW-Authenticate header.
pub fn invalid_client_response(realm: &str, description: &str) -> Response {
    let sanitized = description.replace('"', "'");
    let body = json!({
        "error": "invalid_client",
        "error_description": sanitized,
    });
    let mut response = (StatusCode::UNAUTHORIZED, Json(body)).into_response();
    let header_value = format!("Basic realm=\"{realm}\", error=\"invalid_client\"");
    let header = HeaderValue::from_str(&header_value).unwrap_or_else(|_| {
        HeaderValue::from_static("Basic realm=\"oauth\", error=\"invalid_client\"")
    });
    response.headers_mut().insert(WWW_AUTHENTICATE, header);
    apply_no_cache_headers(&mut response);
    response
}
