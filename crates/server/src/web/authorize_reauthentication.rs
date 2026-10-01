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

/// An opaque continuation has one spelling and carries no protocol parameters.
fn continuation(value: &str) -> Result<Option<String>, Response> {
    let uri: Uri = value.parse().map_err(|_| invalid())?;
    super::request_admission::validate_raw_query(
        uri.query(),
        super::request_admission::DEFAULT_QUERY_LIMITS,
    )
    .map_err(|_| invalid())?;
    let pairs =
        url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()).collect::<Vec<_>>();
    if !pairs.iter().any(|(key, _)| key == PARAM) {
        return Ok(None);
    }
    if pairs.len() != 1
        || pairs[0].0 != PARAM
        || !valid_token(&pairs[0].1)
        || value != format!("/authorize?{PARAM}={}", pairs[0].1)
    {
        return Err(invalid());
    }
    Ok(Some(pairs[0].1.to_string()))
}

pub(super) fn snapshot(ctx: &AuthorizeRequestContext) -> Result<Value, Response> {
    super::authorization_snapshot::AuthorizationSnapshot::encode(ctx).map_err(|_| unavailable())
}

fn session_snapshot(sid: &str, session: &super::auth_session::AuthSession) -> Value {
    json!({"session_sha256":digest(sid),"subject":session.user_id,
        "auth_time":session.auth_time_epoch_secs,"acr":session.acr})
}

pub(super) async fn create(
    state: &AppState,
    ctx: &AuthorizeRequestContext,
) -> Result<(String, String), Response> {
    // A consumed receipt cannot start a replacement interaction. This also
    // preserves the former URI-token guard when a positive max_age has elapsed.
    if ctx.reauthenticated {
        return Err(invalid());
    }
    let token = random_token()?;
    let browser = random_token()?;
    storage::create(state, ctx, "/authorize", &token, &browser).await?;
    Ok((
        format!("/authorize?{PARAM}={token}"),
        format!("{COOKIE}={browser}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300"),
    ))
}

async fn rebuild(
    state: &AppState,
    pending: &storage::Pending,
    request_id: String,
) -> Result<AuthorizeRequestContext, Response> {
    let saved = super::authorization_snapshot::AuthorizationSnapshot::decode(&pending.snapshot)
        .map_err(|_| invalid())?;
    if saved.reauthenticated || !saved.matches_client(&pending.client_id) {
        return Err(invalid());
    }
    let ctx = super::authorize_context::build_authorize_input_context(
        state,
        saved.input,
        saved.par_continuation,
        &state.issuer,
        request_id,
    )
    .await?;
    if ctx.req.client_id != pending.client_id || snapshot(&ctx)? != pending.snapshot {
        return Err(invalid());
    }
    Ok(ctx)
}

pub(super) async fn bind_form(
    state: &AppState,
    headers: &HeaderMap,
    return_to: Option<&str>,
    csrf: &str,
) -> Result<(), Response> {
    let Some(token) = return_to.map(continuation).transpose()?.flatten() else {
        return Ok(());
    };
    let browser = browser_cookie(headers)?;
    let pending = storage::load(state, &token, &browser, None).await?;
    let saved = super::authorization_snapshot::AuthorizationSnapshot::decode(&pending.snapshot)
        .map_err(|_| invalid())?;
    if saved.reauthenticated || !saved.matches_client(&pending.client_id) {
        return Err(invalid());
    }
    storage::bind_form(state, &pending, &token, &browser, csrf).await
}

/// Return only the revalidated, bound request for the local step-up adapter.
pub(super) async fn complete(
    state: &AppState,
    headers: &HeaderMap,
    return_to: Option<&str>,
    csrf: &str,
    sid: &str,
) -> Result<Option<AuthorizeRequestContext>, Response> {
    let Some(token) = return_to.map(continuation).transpose()?.flatten() else {
        return Ok(None);
    };
    let browser = browser_cookie(headers)?;
    let pending = storage::load(state, &token, &browser, None).await?;
    let ctx = rebuild(state, &pending, pending.id.to_string()).await?;
    let session = state
        .browser_auth
        .auth_sessions
        .try_get_async(sid.to_string())
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(invalid)?;
    storage::complete(
        state,
        &pending,
        &token,
        &browser,
        csrf,
        &session_snapshot(sid, &session),
    )
    .await?;
    Ok(Some(ctx))
}

/// Load first, then reapply policy and compare, and finally atomically consume.
pub(super) async fn resume_context(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    request_id: String,
) -> Result<Option<AuthorizeRequestContext>, Response> {
    let Some(token) = continuation(&uri.to_string())? else {
        return Ok(None);
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
    let session = session_snapshot(&sid, &session);
    let pending = storage::load(state, &token, &browser, Some(&session)).await?;
    let mut ctx = rebuild(state, &pending, request_id).await?;
    storage::consume(state, &pending, &token, &browser, &session).await?;
    ctx.reauthenticated = true;
    ctx.reauthentication_session = Some(session);
    Ok(Some(ctx))
}

/// The session selected for the subsequent decision must still be the receipt's
/// session, including subject, authentication time and ACR (also after consent).
pub(super) fn verify_session(
    ctx: &AuthorizeRequestContext,
    sid: Option<&str>,
    session: Option<&super::auth_session::AuthSession>,
) -> Result<(), Response> {
    if !ctx.reauthenticated {
        return Ok(());
    }
    let actual = session_snapshot(sid.ok_or_else(invalid)?, session.ok_or_else(invalid)?);
    if ctx.reauthentication_session.as_ref() != Some(&actual) {
        return Err(invalid());
    }
    Ok(())
}
