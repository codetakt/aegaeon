use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn confirmation(ticket: &str, csrf: &str, name: &str) -> Response {
    let html = format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Open learning tool</title><main><h1>Open {name}?</h1><p>This launch shares your identifier, authorized roles and configured attributes with this tool.</p><form method="post" action="/lti/launch/{ticket}"><input type="hidden" name="csrf" value="{csrf}"><button type="submit" name="decision" value="approve">Continue</button><button type="submit" name="decision" value="deny">Cancel</button></form></main></html>"#,
        name = escape(name),
        ticket = escape(ticket),
        csrf = escape(csrf)
    );
    let mut response = super::super::local_auth_support::local_auth_response(StatusCode::OK, html);
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    response
}

pub(super) fn redirect(url: &str) -> Result<Response, crate::lti::LtiError> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(url).map_err(|_| crate::lti::LtiError::Invalid)?,
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    crate::util::apply_no_cache_headers(&mut response);
    Ok(response)
}

pub(super) fn cancelled() -> Response {
    super::super::local_auth_support::local_auth_response(StatusCode::OK,"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Launch cancelled</title><main><p>Launch cancelled.</p></main></html>".into())
}
