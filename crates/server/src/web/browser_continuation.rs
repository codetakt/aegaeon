//! Complete an authentication POST before navigating to its trusted destination.

use axum::{
    body::Body,
    response::{IntoResponse, Response},
};
use http::{header, HeaderValue, StatusCode};

use super::validate_return_to;
use crate::util;

const CONTINUE_SCRIPT: &str = "window.location.replace(document.getElementById('aegaeon-continuation').getAttribute('href'));";
const INVALID_HTML: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Unable to continue</title></head><body><p>The server could not continue this request.</p></body></html>";

fn escape_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn html_headers(response: &mut Response) {
    // These describe the old response body or redirect, not the new document.
    for name in [
        header::LOCATION,
        header::CONTENT_LENGTH,
        header::CONTENT_ENCODING,
        header::TRANSFER_ENCODING,
    ] {
        response.headers_mut().remove(name);
    }
    util::apply_auth_html_security_headers(response);
}

fn invalid(mut response: Response, status: StatusCode) -> Response {
    *response.status_mut() = status;
    *response.body_mut() = Body::from(INVALID_HTML);
    html_headers(&mut response);
    response
}

fn navigate(mut response: Response, destination: &str) -> Response {
    let nonce = aegaeon_crypto::rand::random_base64url(16);
    let csp = format!("default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'none'; script-src 'nonce-{nonce}'");
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        return invalid(response, StatusCode::INTERNAL_SERVER_ERROR);
    };
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Continue</title></head><body><p><a id=\"aegaeon-continuation\" href=\"{}\">Continue</a></p><script nonce=\"{nonce}\">{CONTINUE_SCRIPT}</script></body></html>",
        escape_attribute(destination),
    );
    *response.status_mut() = StatusCode::OK;
    *response.body_mut() = Body::from(html);
    html_headers(&mut response);
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, csp);
    response
}

/// The local form parser already validated this value. Revalidate without
/// normalizing it again, so the authorization query and its bindings stay exact.
pub(super) fn local_response(return_to: &str) -> Result<Response, Response> {
    match validate_return_to(Some(return_to.to_string())) {
        Ok(Some(validated)) if validated == return_to => {
            Ok(navigate(StatusCode::OK.into_response(), return_to))
        }
        _ => Err(invalid(
            StatusCode::BAD_REQUEST.into_response(),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// Only call on a trusted authorization result after the consent decision.
/// Early origin/session/transaction failures must never reach this conversion.
/// Existing form_post/JSON/error bodies with no Location remain byte-for-byte.
pub(super) fn authorization_response(response: Response) -> Response {
    if !response.status().is_redirection() {
        return if response.headers().contains_key(header::LOCATION) {
            invalid(response, StatusCode::INTERNAL_SERVER_ERROR)
        } else {
            response
        };
    }
    if !matches!(response.status(), StatusCode::FOUND | StatusCode::SEE_OTHER) {
        return invalid(response, StatusCode::INTERNAL_SERVER_ERROR);
    }
    let destination = match util::single_header_str(response.headers(), "location") {
        Ok(Some(value))
            if !value.is_empty()
                && value.trim() == value
                && !value.contains('\\')
                && !value.chars().any(char::is_control)
                && crate::dcr::validate_redirect_uris(&[value.to_string()]).is_ok() =>
        {
            value.to_string()
        }
        _ => return invalid(response, StatusCode::INTERNAL_SERVER_ERROR),
    };
    // Keep the original Location bytes; validation does not reserialize the URL.
    navigate(response, &destination)
}

#[cfg(test)]
mod tests;
