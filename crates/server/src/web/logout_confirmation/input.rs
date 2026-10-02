use super::{invalid, storage, unavailable, Browser};
use crate::web::{
    oidc_request_input::{admit_oidc_form, admit_oidc_query, OidcEndpoint, OidcParameters},
    request_admission::{enforce_content_type, DEFAULT_QUERY_LIMITS},
    AppState, AUTH_SESSION_COOKIE_NAME,
};
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, HeaderValue, Method, Request, Uri},
    response::Response,
};

pub(super) fn valid_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(super) async fn parameters(
    state: &AppState,
    uri: &Uri,
    request: Request<Body>,
    endpoint: OidcEndpoint,
) -> Result<OidcParameters, Response> {
    if request.method() != Method::POST {
        return admit_oidc_query(endpoint, uri).map_err(|e| e.into_response(&state.issuer));
    }
    // Protocol parameters are exclusively in the form on POST. Reject a query
    // instead of choosing between two potentially conflicting input sources.
    if uri.query().is_some_and(|q| !q.is_empty()) {
        return Err(invalid());
    }
    enforce_content_type(
        request.headers(),
        "application/x-www-form-urlencoded",
        &state.issuer,
    )?;
    let bytes = to_bytes(request.into_body(), DEFAULT_QUERY_LIMITS.max_bytes())
        .await
        .map_err(|_| invalid())?;
    admit_oidc_form(endpoint, &bytes).map_err(|e| e.into_response(&state.issuer))
}

// Reject duplicate cookie names as well as duplicate Cookie headers. Do not use
// the first-value helper at a confirmation boundary.
fn cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>, Response> {
    let header = crate::util::single_header_str(headers, "cookie").map_err(|_| invalid())?;
    let mut found = None;
    for part in header
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let (key, value) = part.split_once('=').ok_or_else(invalid)?;
        if key.trim() == name {
            if found.is_some() || value.is_empty() || value.trim() != value {
                return Err(invalid());
            }
            found = Some(value.to_string());
        }
    }
    Ok(found)
}

fn cookie_name(token: &str) -> String {
    format!("__Host-aegaeon-logout-{}", storage::digest(token))
}

pub(super) fn binding(headers: &HeaderMap, token: &str) -> Result<String, Response> {
    if !valid_token(token) {
        return Err(invalid());
    }
    cookie(headers, &cookie_name(token))?
        .filter(|v| valid_token(v))
        .ok_or_else(invalid)
}

pub(super) fn set_cookie(
    response: &mut Response,
    token: &str,
    secret: Option<&str>,
) -> Result<(), Response> {
    let max_age = if secret.is_some() { 300 } else { 0 };
    let value = format!(
        "{}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
        cookie_name(token),
        secret.unwrap_or("")
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&value).map_err(|_| unavailable("cookie_encoding"))?,
    );
    Ok(())
}

pub(super) async fn browser(state: &AppState, headers: &HeaderMap) -> Result<Browser, Response> {
    let Some(id) = cookie(headers, AUTH_SESSION_COOKIE_NAME)? else {
        return Ok(Browser(None));
    };
    if uuid::Uuid::parse_str(&id).is_err() {
        return Err(invalid());
    }
    let session = state
        .browser_auth
        .auth_sessions
        .try_get_async(id.clone())
        .await
        .map_err(|_| unavailable("auth_session_lookup"))?;
    Ok(Browser(session.map(|s| (id, s))))
}

pub(super) fn same_origin(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let origin = crate::util::single_header_str(headers, "origin").map_err(|_| invalid())?;
    let expected = url::Url::parse(&state.issuer)
        .map_err(|_| unavailable("issuer_origin"))?
        .origin()
        .ascii_serialization();
    if origin != Some(expected.as_str()) {
        return Err(invalid());
    }
    Ok(())
}
