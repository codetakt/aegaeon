use super::Browser;
use crate::web::{
    local_auth_support::local_auth_response,
    presentation::{escape, fill, text, Page, Presentation},
};
use axum::{
    http::{header::REFERRER_POLICY, HeaderValue, StatusCode},
    response::Response,
};

pub(super) fn form(presentation: Presentation<'_>, token: &str, browser: &Browser) -> Response {
    let messages = presentation.messages();
    let session = browser.subject().map_or_else(
        || text(messages.no_active_sign_in),
        |subject| {
            let account = format!("<strong><bdi>{}</bdi></strong>", escape(subject));
            fill(messages.signed_in_as, &[("account", &account)])
        },
    );
    let main = format!(
        r#"<h1>{heading}</h1><p>{session}</p><p>{requested}</p>
<form method="post" action="/logout/confirm"><input type="hidden" name="transaction" value="{token}">
<div class="actions"><button type="submit" name="decision" value="confirm">{confirm}</button>
<button type="submit" name="decision" value="cancel" class="secondary">{cancel}</button></div></form>"#,
        heading = text(messages.sign_out_heading),
        requested = text(messages.sign_out_requested),
        token = escape(token),
        confirm = text(messages.confirm_sign_out),
        cancel = text(messages.cancel),
    );
    let mut response = local_auth_response(
        StatusCode::OK,
        Page::new(presentation, messages.sign_out_heading, &main).render(),
    );
    // Keep the real browser's same-origin form Origin while suppressing
    // cross-origin referrers. `no-referrer` produces Origin: null in Chromium.
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    response
}

pub(super) fn result(presentation: Presentation<'_>, cancelled: bool) -> Response {
    let messages = presentation.messages();
    let (heading, body) = if cancelled {
        (
            messages.sign_out_cancelled_heading,
            messages.sign_out_cancelled,
        )
    } else {
        (messages.signed_out_heading, messages.signed_out)
    };
    let main = format!("<h1>{}</h1><p>{}</p>", text(heading), text(body));
    local_auth_response(
        StatusCode::OK,
        Page::new(presentation, heading, &main).render(),
    )
}
