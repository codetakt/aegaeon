use axum::{
    extract::Extension,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use super::{Error, UserinfoEndpoint};
use crate::middleware::tls::normalize_forwarded_client_cert;
use crate::middleware::DpopBinding;
use crate::util;

/// Axum handler for userinfo endpoint
pub async fn userinfo_handler(
    headers: HeaderMap,
    Extension(endpoint): Extension<Arc<UserinfoEndpoint>>,
    binding: Option<Extension<DpopBinding>>,
) -> impl IntoResponse {
    let auth_header = match util::single_header_str(&headers, header::AUTHORIZATION.as_str()) {
        Ok(Some(value)) => value,
        Ok(None) => "",
        Err(err) => {
            let description = err.description("Authorization");
            return userinfo_json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(&description),
                true,
            );
        }
    };
    let mtls_fingerprint = match util::single_header_str(&headers, "x-forwarded-client-cert") {
        Ok(Some(value)) if normalize_forwarded_client_cert(value).is_some() => Some(value),
        Ok(Some(_)) => {
            return userinfo_json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("x-forwarded-client-cert header contains an invalid value"),
                true,
            );
        }
        Ok(None) => None,
        Err(err) => {
            let description = err.description("x-forwarded-client-cert");
            return userinfo_json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(&description),
                true,
            );
        }
    };

    let binding_ref = binding.as_ref().map(|Extension(binding)| binding);

    match endpoint
        .handle(auth_header, binding_ref, mtls_fingerprint)
        .await
    {
        Ok(response) => response.into_response(),
        Err(Error::InvalidToken) => {
            userinfo_json_error_response(StatusCode::UNAUTHORIZED, "invalid_token", None, true)
        }
        Err(Error::InsufficientScope) => {
            userinfo_json_error_response(StatusCode::FORBIDDEN, "insufficient_scope", None, true)
        }
        Err(Error::InvalidRequest(message)) => userinfo_json_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(message.as_str()),
            true,
        ),
        Err(Error::ServerError(_)) => userinfo_json_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("userinfo endpoint failed internally"),
            false,
        ),
    }
}

fn userinfo_json_error_response(
    status: StatusCode,
    error: &'static str,
    description: Option<&str>,
    authenticate: bool,
) -> Response {
    let mut body = json!({ "error": error });
    if let Some(description) = description {
        body["error_description"] = json!(description);
    }
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if authenticate {
        let value = format!("Bearer realm=\"aegaeon\", error=\"{error}\"");
        if let Ok(value) = HeaderValue::from_str(&value) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
    }
    response
}
