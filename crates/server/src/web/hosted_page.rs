//! Same-origin invitation mail landing and browser UI.
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use super::presentation::{escape as attribute, Page};

mod fragment;
pub(super) use fragment::{parse_fragment, MailLink};

const SCRIPT: &str = include_str!("hosted_page/landing.js");
const SCREENS: &str = include_str!("hosted_page/screens.js");

pub(super) fn landing(issuer: &str, environment_id: Uuid, csrf: &str, now: i64) -> Response {
    let nonce = aegaeon_crypto::rand::random_base64url(24);
    let csp = format!(
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'self'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; img-src data:"
    );
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let script = format!(
        r#"<script nonce="{nonce}" data-issuer="{}" data-environment="{environment_id}" data-csrf="{}" data-now="{now}">(() => {{ "use strict";
{SCRIPT}
{SCREENS}
start();
}})();</script>"#,
        attribute(issuer),
        attribute(csrf),
    );
    let html = Page {
        style_nonce: Some(&nonce),
        after_main: &script,
        referrer: Some("no-referrer"),
        ..Page::new(
            "Organization invitation",
            r#"<h1>Organization invitation</h1><div id="view" aria-live="polite"><p>Opening the invitation…</p></div><noscript>Enable JavaScript and reopen the link from your email.</noscript>"#,
        )
    }
    .render();
    let mut response = (StatusCode::OK, html).into_response();
    crate::util::apply_auth_html_security_headers(&mut response);
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, csp);
    response
}

#[cfg(test)]
mod tests;
