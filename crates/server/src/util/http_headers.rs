use axum::response::Response;
use http::{
    header::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, PRAGMA, REFERRER_POLICY,
        X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    },
    HeaderMap, HeaderValue,
};

const AUTH_HTML_CSP: &str = "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; img-src 'none'; script-src 'none'; style-src 'unsafe-inline'";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleHeaderError {
    Multiple,
    InvalidValue,
}

impl SingleHeaderError {
    #[must_use]
    pub fn description(self, header_name: &str) -> String {
        match self {
            Self::Multiple => {
                format!("{header_name} header must not be specified multiple times")
            }
            Self::InvalidValue => format!("{header_name} header contains an invalid value"),
        }
    }
}

pub fn apply_no_cache_headers(response: &mut Response) {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
}

pub fn apply_auth_html_security_headers(response: &mut Response) {
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(AUTH_HTML_CSP),
    );
    response
        .headers_mut()
        .insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    apply_no_cache_headers(response);
}

/// Return exactly one header value, rejecting duplicate or non-ASCII values.
///
/// Security-sensitive OAuth headers are not list-valued. Accepting the first
/// value would let intermediaries and endpoints disagree on the credential that
/// actually authenticated the request.
///
/// # Errors
///
/// Returns [`SingleHeaderError::Multiple`] when the request contains more than
/// one field with the same name, and [`SingleHeaderError::InvalidValue`] when
/// the single value cannot be represented as `str`.
pub fn single_header_str<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, SingleHeaderError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(SingleHeaderError::Multiple);
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| SingleHeaderError::InvalidValue)
}
