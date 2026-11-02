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

pub(super) fn confirmation(
    ticket: &str,
    csrf: &str,
    name: &str,
    initiate_login_uri: &str,
) -> Result<Response, crate::lti::LtiError> {
    let destination =
        url::Url::parse(initiate_login_uri).map_err(|_| crate::lti::LtiError::Unavailable)?;
    if destination.scheme() != "https"
        || destination.host_str().is_none()
        || !destination.username().is_empty()
        || destination.password().is_some()
        || destination.fragment().is_some()
    {
        return Err(crate::lti::LtiError::Unavailable);
    }
    // Only the stored, validated Tool origin can receive the consent POST's
    // redirect. URL serialization excludes path/query text and header injection.
    let policy = format!(
        "default-src 'none'; base-uri 'none'; form-action 'self' {}; frame-ancestors 'none'; img-src 'none'; script-src 'none'; style-src 'unsafe-inline'",
        destination.origin().ascii_serialization()
    );
    let html = format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Open learning tool</title><main><h1>Open {name}?</h1><p>This launch shares your identifier, authorized roles and configured attributes with this tool.</p><form method="post" action="/lti/launch/{ticket}"><input type="hidden" name="csrf" value="{csrf}"><button type="submit" name="decision" value="approve">Continue</button><button type="submit" name="decision" value="deny">Cancel</button></form></main></html>"#,
        name = escape(name),
        ticket = escape(ticket),
        csrf = escape(csrf)
    );
    let mut response = super::super::local_auth_support::local_auth_response(StatusCode::OK, html);
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy).map_err(|_| crate::lti::LtiError::Unavailable)?,
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    Ok(response)
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
