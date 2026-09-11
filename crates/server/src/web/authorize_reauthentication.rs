//! Local authentication receipts never change signed authorization parameters.
mod storage;

use super::{authorize_context::AuthorizeRequestContext, AppState};
use axum::{
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

const PARAM: &str = "aeg_login_continue";
const COOKIE: &str = "aegaeon_authorization_login";

fn error(status: StatusCode, code: &str, description: &str) -> Response {
    let mut response = (
        status,
        Json(json!({"error":code,"error_description":description})),
    )
        .into_response();
    crate::util::apply_no_cache_headers(&mut response);
    response
}

fn invalid() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "authentication continuation is invalid, expired or already used; restart authorization",
    )
}

fn unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "authentication continuation storage unavailable",
    )
}

fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(value.as_bytes()))
}

fn random_token() -> Result<String, Response> {
    let mut bytes = [0u8; 32];
    aegaeon_crypto::rand::fill_random(&mut bytes).map_err(|_| unavailable())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn browser_cookie(headers: &HeaderMap) -> Result<String, Response> {
    let header = crate::util::single_header_str(headers, "cookie")
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let cookies = header
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .filter(|(key, _)| *key == COOKIE)
        .collect::<Vec<_>>();
    if cookies.len() != 1 || !valid_token(cookies[0].1) {
        return Err(invalid());
    }
    Ok(cookies[0].1.to_string())
}

/// Returns the token and URI with only the internal login continuation removed.
fn continuation(value: &str) -> Result<Option<(String, String)>, Response> {
    let uri: Uri = value.parse().map_err(|_| invalid())?;
    super::request_admission::validate_raw_query(
        uri.query(),
        super::request_admission::DEFAULT_QUERY_LIMITS,
    )
    .map_err(|_| invalid())?;
    let mut token = None;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()) {
        if key == PARAM {
            if token.is_some() || !valid_token(&value) {
                return Err(invalid());
            }
            token = Some(value.into_owned());
        } else {
            query.append_pair(&key, &value);
        }
    }
    if token.is_some() && (uri.path() != "/authorize" || uri.authority().is_some()) {
        return Err(invalid());
    }
    Ok(token.map(|token| (token, format!("{}?{}", uri.path(), query.finish()))))
}

pub(super) fn snapshot(ctx: &AuthorizeRequestContext) -> Result<Value, Response> {
    Ok(
        json!({"request": serde_json::to_value(&ctx.req).map_err(|_| unavailable())?,
        "prompt": ctx.prompt, "response_mode": format!("{:?}",ctx.response_mode)}),
    )
}

fn session_snapshot(sid: &str, session: &super::auth_session::AuthSession) -> Value {
    json!({"session_sha256":digest(sid),"subject":session.user_id,
        "auth_time":session.auth_time_epoch_secs,"acr":session.acr})
}

pub(super) async fn create(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
    uri: &Uri,
) -> Result<(String, String), Response> {
    let canonical = {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()) {
            if key == PARAM {
                return Err(invalid());
            }
            if key != "aeg_par_continue" {
                query.append_pair(&key, &value);
            }
        }
        if let Some(value) = ctx.par_authorize_continuation.as_deref() {
            query.append_pair("aeg_par_continue", value);
        }
        format!("/authorize?{}", query.finish())
    };
    let token = random_token()?;
    let browser = random_token()?;
    storage::create(state, ctx, &canonical, &token, &browser).await?;
    Ok((
        format!("{canonical}&{PARAM}={token}"),
        format!("{COOKIE}={browser}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300"),
    ))
}

pub(super) async fn bind_form(
    state: &AppState,
    headers: &HeaderMap,
    return_to: Option<&str>,
    csrf: &str,
) -> Result<(), Response> {
    let Some((token, uri)) = return_to.map(continuation).transpose()?.flatten() else {
        return Ok(());
    };
    let browser = browser_cookie(headers)?;
    storage::bind_form(state, &token, &uri, &browser, csrf).await
}

pub(super) async fn complete(
    state: &AppState,
    headers: &HeaderMap,
    return_to: Option<&str>,
    csrf: &str,
    sid: &str,
) -> Result<(), Response> {
    let Some((token, uri)) = return_to.map(continuation).transpose()?.flatten() else {
        return Ok(());
    };
    let browser = browser_cookie(headers)?;
    let session = state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.to_string())
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(invalid)?;
    storage::complete(
        state,
        &token,
        &uri,
        &browser,
        csrf,
        &session_snapshot(sid, &session),
    )
    .await
}

pub(super) async fn resume(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    ctx: &AuthorizeRequestContext,
) -> Result<bool, Response> {
    let Some((token, canonical)) = continuation(&uri.to_string())? else {
        return Ok(false);
    };
    let browser = browser_cookie(headers)?;
    let sid = super::form_helpers::auth_session_cookie(headers)
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let session = state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.clone())
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(invalid)?;
    storage::consume(
        state,
        ctx,
        &token,
        &canonical,
        &browser,
        &session_snapshot(&sid, &session),
    )
    .await?;
    Ok(true)
}
