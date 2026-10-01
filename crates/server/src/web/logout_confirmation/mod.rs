//! RP logout can only end the browser session explicitly presented and approved.
mod effects;
mod input;
mod rendering;
mod storage;

use super::{
    auth_session::AuthSession,
    logout_context::{resolve_logout_context, validate_post_logout_redirect_uri, LogoutQuery},
    oauth_errors::no_cache_json_error_with_iss,
    oidc_request_input::OidcEndpoint,
    request_admission::enforce_no_credentials_in_logout_uri,
    AppState,
};
use axum::{
    body::Body,
    extract::{ConnectInfo, OriginalUri, State},
    http::{header, HeaderValue, Method, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

struct Browser(Option<(String, AuthSession)>);
impl Browser {
    fn digest(&self) -> Option<String> {
        self.0.as_ref().map(|(id, _)| storage::digest(id))
    }
    fn subject(&self) -> Option<&str> {
        self.0.as_ref().map(|(_, s)| s.user_id.as_str())
    }
}

fn invalid() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "logout confirmation could not be validated; start a new logout request",
    )
}
fn error(status: StatusCode, code: &str, message: &str) -> Response {
    let mut response = (
        status,
        axum::Json(serde_json::json!({"error":code,"error_description":message})),
    )
        .into_response();
    crate::util::apply_no_cache_headers(&mut response);
    response
}

fn unavailable(step: &'static str) -> Response {
    tracing::error!(step, "logout confirmation could not be completed");
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "logout could not be completed; a new confirmation may be required",
    )
}

fn validate(state: &AppState, query: &LogoutQuery) -> Result<Option<String>, Response> {
    let cfg = state
        .oidc
        .config
        .as_ref()
        .filter(|cfg| cfg.logout_enabled)
        .ok_or_else(|| {
            no_cache_json_error_with_iss(StatusCode::NOT_FOUND, "not_found", None, &state.issuer)
        })?;
    let context = resolve_logout_context(state, cfg, query, &state.issuer)?;
    if let Some(context) = &context {
        validate_post_logout_redirect_uri(state, &context.client_id, query, &state.issuer)?;
    }
    Ok(context.map(|ctx| ctx.client_id))
}

fn transport(
    state: &AppState,
    remote: SocketAddr,
    request: &Request<Body>,
    uri: &Uri,
) -> Result<(), Response> {
    state
        .transport
        .enforce(Some(remote), request.headers())
        .map_err(|kind| super::transport_rejection(state, kind))?;
    enforce_no_credentials_in_logout_uri(uri, &state.issuer)
}

async fn initiate(
    state: &AppState,
    remote: SocketAddr,
    uri: &Uri,
    request: Request<Body>,
) -> Result<Response, Response> {
    transport(state, remote, &request, uri)?;
    let head = request.method() == Method::HEAD;
    let source = state
        .transport
        .rate_limit_subject(Some(remote), request.headers())
        .map_err(|kind| super::transport_rejection(state, kind))?;
    super::authorization_transactions::admit_source(state, &source).await?;
    let query: LogoutQuery = input::parameters(state, uri, request, OidcEndpoint::Logout)
        .await?
        .deserialize()
        .map_err(|e| e.into_response(&state.issuer))?;
    validate(state, &query)?;
    if head {
        let mut response = StatusCode::OK.into_response();
        crate::util::apply_no_cache_headers(&mut response);
        return Ok(response);
    }
    let (token, secret) = storage::create(state, &query).await?;
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/logout/confirm?transaction={token}"))
            .map_err(|_| unavailable("continuation"))?,
    );
    input::set_cookie(&mut response, &token, Some(&secret))?;
    crate::util::apply_no_cache_headers(&mut response);
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    Ok(response)
}

pub(super) async fn start(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    match initiate(&state, remote, &uri, request).await {
        Ok(response) | Err(response) => response,
    }
}

async fn show(
    state: &AppState,
    remote: SocketAddr,
    uri: &Uri,
    request: Request<Body>,
) -> Result<Response, Response> {
    transport(state, remote, &request, uri)?;
    let head = request.method() == Method::HEAD;
    let headers = request.headers().clone();
    let parameters =
        input::parameters(state, uri, request, OidcEndpoint::LogoutConfirmation).await?;
    let [(name, token)] = parameters.as_pairs() else {
        return Err(invalid());
    };
    if name != "transaction" {
        return Err(invalid());
    }
    let secret = input::binding(&headers, token)?;
    let pending = storage::load(state, token, &secret).await?;
    let client = validate(state, &pending.query)?;
    let browser = input::browser(state, &headers).await?;
    if !head {
        storage::present(state, &pending, &browser).await?;
    }
    Ok(rendering::form(token, &browser, client.as_deref()))
}

pub(super) async fn present(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    match show(&state, remote, &uri, request).await {
        Ok(response) | Err(response) => response,
    }
}

async fn process_decision(
    state: &AppState,
    remote: SocketAddr,
    uri: &Uri,
    request: Request<Body>,
) -> Result<Response, Response> {
    transport(state, remote, &request, uri)?;
    input::same_origin(state, request.headers())?;
    let headers = request.headers().clone();
    let parameters =
        input::parameters(state, uri, request, OidcEndpoint::LogoutConfirmation).await?;
    if parameters.as_pairs().len() != 2 {
        return Err(invalid());
    }
    #[derive(serde::Deserialize)]
    struct Decision {
        transaction: String,
        decision: String,
    }
    let fields: Decision = parameters
        .deserialize()
        .map_err(|e| e.into_response(&state.issuer))?;
    if !matches!(fields.decision.as_str(), "confirm" | "cancel") {
        return Err(invalid());
    }
    let secret = input::binding(&headers, &fields.transaction)?;
    let pending = storage::load(state, &fields.transaction, &secret).await?;
    let browser = input::browser(state, &headers).await?;
    let client = validate(state, &pending.query)?;
    storage::consume(
        state,
        &pending,
        &browser,
        &fields.transaction,
        &secret,
        &fields.decision,
    )
    .await?;
    let mut response = if fields.decision == "cancel" {
        rendering::result(true)
    } else {
        match effects::complete(
            state,
            &browser,
            &pending.query,
            client.as_deref(),
            &super::request_id_from_headers(&headers),
        )
        .await
        {
            Ok(response) | Err(response) => response,
        }
    };
    input::set_cookie(&mut response, &fields.transaction, None)?;
    Ok(response)
}

pub(super) async fn decide(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    match process_decision(&state, remote, &uri, request).await {
        Ok(response) | Err(response) => response,
    }
}

#[cfg(test)]
mod tests;
