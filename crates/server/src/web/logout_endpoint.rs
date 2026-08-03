use super::form_helpers::{apply_auth_session_clear_cookie, auth_session_cookie};
use super::logout_context::{
    logout_events_from_context, resolve_logout_context, validate_post_logout_redirect_uri,
    LogoutQuery,
};
use super::logout_dispatch::dispatch_backchannel_logout_if_enabled;
use super::oauth_errors::{no_cache_header_error, no_cache_json_error_with_iss};
use super::request_admission::enforce_no_credentials_in_logout_uri;
use super::upstream_logout_incidents::{
    hash_upstream_logout_secret, invalid_logout_relay_state_response,
    persisted_logout_incident_response_by_hash,
};
use super::upstream_logout_sessions::{
    build_upstream_logout_redirect_target, build_upstream_logout_redirect_target_with_relay,
    upstream_logout_relay_store_unavailable_response,
};
use super::{
    auth_session_store_logout_error_response, no_cache_redirect_response, request_id_from_headers,
    transport_rejection, AppState,
};
use axum::{
    extract::{ConnectInfo, OriginalUri, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::net::SocketAddr;

use crate::util;

fn no_cache_redirect_clear_session_response(location: &str) -> Response {
    let mut response = no_cache_redirect_response(location);
    apply_auth_session_clear_cookie(&mut response);
    response
}

fn logout_ok_response(issuer_base: &str, client_id: Option<&str>) -> Response {
    let mut body = serde_json::json!({
        "logout": "ok",
        "iss": issuer_base,
    });
    if let Some(client_id) = client_id {
        body["client_id"] = serde_json::json!(client_id);
    }
    let mut response = (StatusCode::OK, Json(body)).into_response();
    util::apply_no_cache_headers(&mut response);
    apply_auth_session_clear_cookie(&mut response);
    response
}

#[derive(Deserialize, Default)]
pub(super) struct UpstreamLogoutCallbackQuery {
    state: Option<String>,
}

struct LogoutRedirectTargets {
    relay: Option<String>,
    upstream: Option<String>,
}

async fn resolve_logout_redirect_targets(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    client_id: &str,
    query: &LogoutQuery,
    request_id: &str,
) -> Result<LogoutRedirectTargets, Response> {
    let current_auth_session_id = auth_session_cookie(headers)
        .map_err(|err| no_cache_header_error(state.issuer.as_str(), "Cookie", err))?;
    let current_auth_session = match current_auth_session_id.as_deref() {
        Some(sid) => state
            .browser_auth
            .auth_sessions
            .try_get_async(sid.to_string())
            .await
            .map_err(|err| auth_session_store_logout_error_response(state.issuer.as_str(), &err))?
            .map(|session| (sid.to_string(), session)),
        None => None,
    };
    let relay = match (
        current_auth_session
            .as_ref()
            .and_then(|(_, session)| session.upstream_logout.as_ref()),
        query.post_logout_redirect_uri.as_deref(),
    ) {
        (Some(session), Some(downstream_redirect_uri)) => {
            build_upstream_logout_redirect_target_with_relay(
                state,
                session,
                Some(client_id),
                downstream_redirect_uri,
                query.state.as_deref(),
                current_auth_session
                    .as_ref()
                    .map(|(_, auth_session)| auth_session.user_id.as_str()),
                request_id,
            )
            .await?
        }
        _ => None,
    };
    let upstream = current_auth_session
        .as_ref()
        .and_then(|(_, session)| session.upstream_logout.as_ref())
        .and_then(|session| {
            build_upstream_logout_redirect_target(
                session,
                state.cfg.upstream().outbound_allowed_domains(),
            )
        });

    if let Some(sid) = current_auth_session_id.as_deref() {
        state
            .browser_auth
            .auth_sessions
            .try_delete_async(sid.to_string())
            .await
            .map_err(|err| auth_session_store_logout_error_response(state.issuer.as_str(), &err))?;
    }

    Ok(LogoutRedirectTargets { relay, upstream })
}

pub(super) async fn logout(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
    Query(query): Query<LogoutQuery>,
) -> Response {
    let issuer_base = state.issuer.as_str();
    let request_id = request_id_from_headers(&headers);
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }
    if let Err(response) = enforce_no_credentials_in_logout_uri(&uri, issuer_base) {
        return response;
    }

    let Some(cfg) = state.oidc.config.as_ref().filter(|cfg| cfg.logout_enabled) else {
        return no_cache_json_error_with_iss(StatusCode::NOT_FOUND, "not_found", None, issuer_base);
    };
    let Some(context) = (match resolve_logout_context(&state, cfg, &query, issuer_base) {
        Ok(context) => context,
        Err(response) => return response,
    }) else {
        return logout_ok_response(issuer_base, None);
    };
    if let Err(response) =
        validate_post_logout_redirect_uri(&state, &context.client_id, &query, issuer_base)
    {
        return response;
    }
    let logout_events = match logout_events_from_context(&state, &context, issuer_base).await {
        Ok(events) => events,
        Err(response) => return response,
    };
    dispatch_backchannel_logout_if_enabled(&state, cfg, logout_events).await;
    let targets = match resolve_logout_redirect_targets(
        &state,
        &headers,
        &context.client_id,
        &query,
        &request_id,
    )
    .await
    {
        Ok(targets) => targets,
        Err(response) => return response,
    };

    if let Some(location) = targets.relay.as_deref() {
        return no_cache_redirect_clear_session_response(location);
    }
    if let Some(post_logout_redirect_uri) = query.post_logout_redirect_uri.as_deref() {
        return no_cache_redirect_clear_session_response(&util::append_state(
            post_logout_redirect_uri,
            query.state.as_deref(),
        ));
    }
    if let Some(location) = targets.upstream.as_deref() {
        return no_cache_redirect_clear_session_response(location);
    }

    logout_ok_response(issuer_base, Some(&context.client_id))
}

pub(super) async fn upstream_logout_callback(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(query): Query<UpstreamLogoutCallbackQuery>,
) -> Response {
    let issuer_base = state.issuer.as_str();
    let request_id = request_id_from_headers(&headers);
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }

    let Some(relay_state) = query.state.as_deref() else {
        return no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("logout relay state is required"),
            issuer_base,
        );
    };

    let relay_token_hash = hash_upstream_logout_secret(relay_state);

    match state
        .upstream
        .logout_relay_store
        .try_take_async(relay_state.to_string())
        .await
    {
        Ok(Some(relay)) if relay.incident_id.is_none() => {
            return no_cache_redirect_response(&util::append_state(
                &relay.downstream_redirect_uri,
                relay.downstream_state.as_deref(),
            ));
        }
        Ok(Some(_) | None) => {}
        Err(err) => {
            return match persisted_logout_incident_response_by_hash(
                &state.db_pool,
                &relay_token_hash,
                issuer_base,
                &request_id,
            )
            .await
            {
                Ok(Some(response)) => response,
                Ok(None) | Err(_) => {
                    upstream_logout_relay_store_unavailable_response(&err, issuer_base)
                }
            };
        }
    }

    if let Ok(Some(response)) = persisted_logout_incident_response_by_hash(
        &state.db_pool,
        &relay_token_hash,
        issuer_base,
        &request_id,
    )
    .await
    {
        return response;
    }

    invalid_logout_relay_state_response(issuer_base)
}
