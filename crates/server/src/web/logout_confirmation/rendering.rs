use super::Browser;
use crate::web::{
    local_auth_support::local_auth_response,
    presentation::{escape, Page},
};
use axum::{
    http::{header::REFERRER_POLICY, HeaderValue, StatusCode},
    response::Response,
};

pub(super) fn form(token: &str, browser: &Browser) -> Response {
    let session = browser.subject().map_or_else(
        || "There is no active sign-in in this browser.".to_string(),
        |subject| {
            format!(
                "You are signed in as <strong><bdi>{}</bdi></strong>.",
                escape(subject)
            )
        },
    );
    let main = format!(
        r#"<h1>Sign out of this browser?</h1><p>{session}</p><p>Sign-out was requested for this browser.</p>
<form method="post" action="/logout/confirm"><input type="hidden" name="transaction" value="{token}">
<div class="actions"><button type="submit" name="decision" value="confirm">Confirm sign-out</button>
<button type="submit" name="decision" value="cancel" class="secondary">Cancel</button></div></form>"#,
        token = escape(token)
    );
    let mut response = local_auth_response(
        StatusCode::OK,
        Page::new("Confirm sign-out", &main).render(),
    );
    // Keep the real browser's same-origin form Origin while suppressing
    // cross-origin referrers. `no-referrer` produces Origin: null in Chromium.
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    response
}

pub(super) fn result(cancelled: bool) -> Response {
    let (heading, text) = if cancelled {
        (
            "Sign-out cancelled",
            "Sign-out cancelled. Your session has not been ended.",
        )
    } else {
        ("Signed out", "You are signed out of this browser.")
    };
    local_auth_response(
        StatusCode::OK,
        Page::new(heading, &format!("<h1>{heading}</h1><p>{text}</p>")).render(),
    )
}
