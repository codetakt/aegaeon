//! Complete an authentication POST before navigating to its trusted destination.

use axum::{
    body::Body,
    response::{IntoResponse, Response},
};
use http::{header, HeaderValue, StatusCode};

use super::{
    presentation::{escape as escape_attribute, text, Page, Presentation},
    validate_return_to,
};
use crate::util;

const CONTINUE_SCRIPT: &str = "window.location.replace(document.getElementById('aegaeon-continuation').getAttribute('href'));";

fn invalid_html(presentation: Presentation<'_>) -> String {
    let messages = presentation.messages();
    let main = format!(
        "<h1>{}</h1><p>{}</p>",
        text(messages.unable_to_continue_heading),
        text(messages.unable_to_continue)
    );
    Page::new(presentation, messages.unable_to_continue_heading, &main).render()
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

fn invalid(presentation: Presentation<'_>, mut response: Response, status: StatusCode) -> Response {
    *response.status_mut() = status;
    *response.body_mut() = Body::from(invalid_html(presentation));
    html_headers(&mut response);
    response
}

fn navigate(presentation: Presentation<'_>, mut response: Response, destination: &str) -> Response {
    let nonce = aegaeon_crypto::rand::random_base64url(16);
    let csp = format!("default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'");
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        return invalid(presentation, response, StatusCode::INTERNAL_SERVER_ERROR);
    };
    let messages = presentation.messages();
    let main = format!(
        "<h1>{}</h1><p><a id=\"aegaeon-continuation\" href=\"{}\">{}</a></p>",
        text(messages.continue_heading),
        escape_attribute(destination),
        text(messages.continue_link),
    );
    let script = format!("<script nonce=\"{nonce}\">{CONTINUE_SCRIPT}</script>");
    let html = Page {
        style_nonce: Some(&nonce),
        after_main: &script,
        ..Page::new(presentation, messages.continue_heading, &main)
    }
    .render();
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
pub(super) fn local_response(
    presentation: Presentation<'_>,
    return_to: &str,
) -> Result<Response, Response> {
    match validate_return_to(Some(return_to.to_string())) {
        Ok(Some(validated)) if validated == return_to => Ok(navigate(
            presentation,
            StatusCode::OK.into_response(),
            return_to,
        )),
        _ => Err(invalid(
            presentation,
            StatusCode::BAD_REQUEST.into_response(),
            StatusCode::BAD_REQUEST,
        )),
    }
}

/// Only call on a trusted authorization result after the consent decision.
/// Early origin/session/transaction failures must never reach this conversion.
/// Existing form_post/JSON/error bodies with no Location remain byte-for-byte.
pub(super) fn authorization_response(
    presentation: Presentation<'_>,
    response: Response,
) -> Response {
    if !response.status().is_redirection() {
        return if response.headers().contains_key(header::LOCATION) {
            invalid(presentation, response, StatusCode::INTERNAL_SERVER_ERROR)
        } else {
            response
        };
    }
    if !matches!(response.status(), StatusCode::FOUND | StatusCode::SEE_OTHER) {
        return invalid(presentation, response, StatusCode::INTERNAL_SERVER_ERROR);
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
        _ => return invalid(presentation, response, StatusCode::INTERNAL_SERVER_ERROR),
    };
    // Keep the original Location bytes; validation does not reserialize the URL.
    navigate(presentation, response, &destination)
}

#[cfg(test)]
mod tests;
