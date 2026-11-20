//! Same-origin invitation mail landing and browser UI.
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

mod fragment;
pub(super) use fragment::{parse_fragment, MailLink};

const SCRIPT: &str = include_str!("hosted_page/landing.js");
const SCREENS: &str = include_str!("hosted_page/screens.js");
const STYLE: &str = include_str!("hosted_page/landing.css");

fn attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub(super) fn landing(issuer: &str, environment_id: Uuid, csrf: &str, now: i64) -> Response {
    let nonce = aegaeon_crypto::rand::random_base64url(24);
    let csp = format!(
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'self'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; img-src data:"
    );
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Organization invitation</title><link rel="icon" href="data:,"><style nonce="{nonce}">{STYLE}</style></head>
<body><main><h1>Organization invitation</h1><div id="view" aria-live="polite"><p>Opening the invitation…</p></div><noscript>Enable JavaScript and reopen the link from your email.</noscript></main>
<script nonce="{nonce}" data-issuer="{}" data-environment="{environment_id}" data-csrf="{}" data-now="{now}">(() => {{ "use strict";
{SCRIPT}
{SCREENS}
start();
}})();</script></body></html>"#,
        attribute(issuer),
        attribute(csrf),
    );
    let mut response = (StatusCode::OK, html).into_response();
    crate::util::apply_auth_html_security_headers(&mut response);
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, csp);
    response
}

#[cfg(test)]
mod tests;
