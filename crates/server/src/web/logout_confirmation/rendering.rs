use super::Browser;
use crate::web::local_auth_support::local_auth_response;
use axum::{
    http::{header::REFERRER_POLICY, HeaderValue, StatusCode},
    response::Response,
};

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn form(token: &str, browser: &Browser) -> Response {
    let session = browser.subject().map_or_else(
        || "There is no active sign-in in this browser.".to_string(),
        |subject| format!("You are signed in as <strong>{}</strong>.", escape(subject)),
    );
    let mut response = local_auth_response(
        StatusCode::OK,
        format!(
            r#"<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Confirm sign-out</title><main><h1>Sign out of this browser?</h1><p>{session}</p><p>Sign-out was requested for this browser.</p>
<form method="post" action="/logout/confirm"><input type="hidden" name="transaction" value="{token}">
<button type="submit" name="decision" value="confirm">Confirm sign-out</button>
<button type="submit" name="decision" value="cancel">Cancel</button></form></main></html>"#,
            token = escape(token)
        ),
    );
    // Keep the real browser's same-origin form Origin while suppressing
    // cross-origin referrers. `no-referrer` produces Origin: null in Chromium.
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    response
}

pub(super) fn result(cancelled: bool) -> Response {
    let text = if cancelled {
        "Sign-out cancelled. Your session has not been ended."
    } else {
        "You are signed out of this browser."
    };
    local_auth_response(StatusCode::OK,format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Sign-out</title><main><p>{text}</p></main></html>"))
}
