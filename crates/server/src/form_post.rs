use axum::response::{Html, IntoResponse, Response};
use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, PRAGMA, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use http::HeaderValue;
use std::collections::HashSet;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Query,
    FormPost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseModeParseError {
    Empty,
    Unsupported,
}

/// Parse an OAuth/OIDC `response_mode` value.
///
/// # Errors
///
/// Returns [`ResponseModeParseError`] when the supplied value is blank or not one of the supported
/// response modes.
pub fn parse_response_mode(raw: Option<&str>) -> Result<ResponseMode, ResponseModeParseError> {
    let Some(raw) = raw else {
        return Ok(ResponseMode::Query);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ResponseModeParseError::Empty);
    }
    if trimmed.eq_ignore_ascii_case("query") {
        return Ok(ResponseMode::Query);
    }
    if trimmed.eq_ignore_ascii_case("form_post") {
        return Ok(ResponseMode::FormPost);
    }
    Err(ResponseModeParseError::Unsupported)
}

#[derive(Debug, Clone)]
pub struct FormPostPage {
    pub html: String,
    pub csp: HeaderValue,
}

#[derive(Debug)]
pub enum FormPostError {
    InvalidActionUrl,
    DuplicateField(String),
    InvalidHeaderValue,
}

fn generate_nonce() -> String {
    aegaeon_crypto::rand::random_base64url(16)
}

fn escape_html_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn build_csp_header(action_url: &str, nonce: &str) -> Result<HeaderValue, FormPostError> {
    let parsed = Url::parse(action_url).map_err(|_| FormPostError::InvalidActionUrl)?;
    let origin = parsed.origin().ascii_serialization();
    if origin == "null" {
        return Err(FormPostError::InvalidActionUrl);
    }
    let value = format!(
        "default-src 'none'; base-uri 'none'; form-action {origin}; frame-ancestors 'none'; script-src 'nonce-{nonce}';"
    );
    HeaderValue::from_str(&value).map_err(|_| FormPostError::InvalidHeaderValue)
}

fn render_form_post(
    action_url: &str,
    fields: &[(&str, &str)],
) -> Result<FormPostPage, FormPostError> {
    let nonce = generate_nonce();
    let csp = build_csp_header(action_url, &nonce)?;
    let action_escaped = escape_html_attr(action_url);

    let mut seen = HashSet::with_capacity(fields.len());
    for (name, _) in fields {
        if !seen.insert(*name) {
            return Err(FormPostError::DuplicateField((*name).to_string()));
        }
    }

    let mut inputs = String::new();
    for (name, value) in fields {
        inputs.push_str("<input type=\"hidden\" name=\"");
        inputs.push_str(&escape_html_attr(name));
        inputs.push_str("\" value=\"");
        inputs.push_str(&escape_html_attr(value));
        inputs.push_str("\">");
    }

    let html = format!(
        "<!DOCTYPE html>\
<html lang=\"en\">\
<head>\
<meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Submitting…</title>\
</head>\
<body>\
<form id=\"aegaeon-form-post\" method=\"post\" action=\"{action_escaped}\">\
{inputs}\
<noscript>\
<p>JavaScript is disabled. Click Continue to proceed.</p>\
<button type=\"submit\">Continue</button>\
</noscript>\
</form>\
<script nonce=\"{nonce}\">(function(){{document.getElementById('aegaeon-form-post').submit();}})();</script>\
</body>\
</html>"
    );

    Ok(FormPostPage { html, csp })
}

fn apply_form_post_headers(response: &mut Response, csp: HeaderValue) {
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(CONTENT_SECURITY_POLICY, csp);
    response
        .headers_mut()
        .insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

/// Build a `form_post` success response for the authorization endpoint.
///
/// # Errors
///
/// Returns [`FormPostError`] when the action URL is invalid, generated headers are malformed, or
/// duplicate form fields are detected.
pub fn authorization_success(
    action_url: &str,
    code: &str,
    state: Option<&str>,
    issuer: &str,
) -> Result<Response, FormPostError> {
    let mut fields = vec![("code", code), ("iss", issuer)];
    if let Some(state) = state {
        fields.push(("state", state));
    }
    let page = render_form_post(action_url, &fields)?;
    let mut response = Html(page.html).into_response();
    apply_form_post_headers(&mut response, page.csp);
    Ok(response)
}

/// Build a `form_post` error response for the authorization endpoint.
///
/// # Errors
///
/// Returns [`FormPostError`] when the action URL is invalid, generated headers are malformed, or
/// duplicate form fields are detected.
pub fn authorization_error(
    action_url: &str,
    error: &str,
    error_description: Option<&str>,
    state: Option<&str>,
    issuer: &str,
) -> Result<Response, FormPostError> {
    let mut fields = vec![("error", error), ("iss", issuer)];
    if let Some(desc) = error_description {
        fields.push(("error_description", desc));
    }
    if let Some(state) = state {
        fields.push(("state", state));
    }
    let page = render_form_post(action_url, &fields)?;
    let mut response = Html(page.html).into_response();
    apply_form_post_headers(&mut response, page.csp);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    async fn response_parts(response: Response) -> Result<(http::HeaderMap, String), String> {
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|err| format!("read form_post response body: {err}"))?;
        let html = String::from_utf8(body.to_vec())
            .map_err(|err| format!("decode form_post response body: {err}"))?;
        Ok((parts.headers, html))
    }

    #[tokio::test]
    async fn authorization_success_escapes_html_attributes() -> TestResult {
        let response = authorization_success(
            "https://client.example/callback",
            "\"><script>alert(1)</script>",
            Some("\" onfocus=\"alert(2)"),
            "https://issuer.example",
        )
        .map_err(|err| format!("build form_post response: {err:?}"))?;
        let (_, html) = response_parts(response).await?;

        assert!(!html.contains("<script>alert(1)</script>"));
        assert_eq!(html.matches("<script").count(), 1);
        assert!(html
            .contains("name=\"code\" value=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
        assert!(html.contains("name=\"state\" value=\"&quot; onfocus=&quot;alert(2)\""));
        Ok(())
    }

    #[tokio::test]
    async fn authorization_success_emits_only_expected_hidden_fields() -> TestResult {
        let response = authorization_success(
            "https://client.example/callback",
            "authorization-code",
            Some("state-value"),
            "https://issuer.example",
        )
        .map_err(|err| format!("build form_post response: {err:?}"))?;
        let (_, html) = response_parts(response).await?;

        assert_eq!(html.matches("<input type=\"hidden\"").count(), 3);
        for name in ["code", "iss", "state"] {
            assert_eq!(html.matches(&format!("name=\"{name}\"")).count(), 1);
        }
        for name in ["error", "error_description"] {
            assert!(!html.contains(&format!("name=\"{name}\"")));
        }
        Ok(())
    }

    #[test]
    fn csp_header_is_strict_and_nonce_changes() -> TestResult {
        let action_url = "https://client.example/callback";
        let fixed = build_csp_header(action_url, "fixed-nonce")
            .map_err(|err| format!("build CSP header: {err:?}"))?;
        let fixed = fixed
            .to_str()
            .map_err(|err| format!("decode CSP header: {err}"))?;

        assert!(fixed.contains("default-src 'none'"));
        assert!(fixed.contains("form-action https://client.example"));
        assert!(fixed.contains("script-src 'nonce-fixed-nonce'"));
        assert!(fixed.contains("frame-ancestors 'none'"));

        let first = render_form_post(action_url, &[("code", "first")])
            .map_err(|err| format!("render first form_post page: {err:?}"))?;
        let second = render_form_post(action_url, &[("code", "second")])
            .map_err(|err| format!("render second form_post page: {err:?}"))?;
        assert_ne!(first.csp, second.csp);
        Ok(())
    }

    #[tokio::test]
    async fn authorization_success_resists_crlf_injection() -> TestResult {
        let response = authorization_success(
            "https://client.example/callback",
            "code\r\nX-Injected: yes\r\n\"><input type=\"hidden\" name=\"evil\" value=\"1",
            Some("state\r\nSet-Cookie: injected=true"),
            "https://issuer.example",
        )
        .map_err(|err| format!("build form_post response: {err:?}"))?;
        let (headers, html) = response_parts(response).await?;

        assert!(!headers.contains_key("x-injected"));
        assert!(!headers.contains_key("set-cookie"));
        for value in headers.values() {
            let value = value
                .to_str()
                .map_err(|err| format!("decode response header: {err}"))?;
            assert!(!value.contains(['\r', '\n']));
        }
        assert_eq!(html.matches("<input type=\"hidden\"").count(), 3);
        assert!(!html.contains("name=\"evil\""));
        assert!(html.contains("&quot;&gt;&lt;input type=&quot;hidden&quot;"));
        Ok(())
    }
}
