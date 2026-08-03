use super::auth_session::AuthSessionTimes;
use super::form_helpers::build_session_set_cookie;
use super::oauth_errors::json_error_with_iss;
use super::request_admission::enforce_no_credentials_in_callback_uri;
use super::upstream_callback_connection::validate_and_hydrate_upstream_callback_connection;
use super::upstream_callback_exchange::perform_upstream_callback_exchange;
use super::upstream_callback_session_failure_audit::record_upstream_callback_session_failure_audit;
use super::upstream_callback_state::{
    consume_upstream_callback_context, handle_upstream_callback_error,
    validate_upstream_callback_issuer, UpstreamCallbackQuery,
};
use super::upstream_callback_users::{
    persist_upstream_callback_refresh_token, record_upstream_callback_audit,
    resolve_upstream_callback_user, sync_upstream_callback_projection,
    UpstreamCallbackUserResolution,
};
use super::upstream_logout_sessions::build_upstream_logout_session;
use super::{
    clock_error_response, create_auth_session_or_error_response_async, no_cache_redirect_response,
    now_epoch_secs, request_id_from_headers, transport_rejection, AppState,
};
use axum::{
    extract::{ConnectInfo, OriginalUri, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use std::net::SocketAddr;

use crate::oidc::{IdToken, OidcDiscovery};
use crate::upstream::UpstreamAuthRequest;

async fn finalize_upstream_callback_response(
    state: &AppState,
    request: &UpstreamAuthRequest,
    discovery: &OidcDiscovery,
    id_token: &IdToken,
    user: &UpstreamCallbackUserResolution,
    request_id: &str,
) -> Response {
    let acr = id_token
        .claims
        .acr
        .clone()
        .or(request.acr.clone())
        .or(state.cfg.default_acr.clone());
    let upstream_logout = build_upstream_logout_session(
        request.logout_policy.as_ref(),
        &request.issuer,
        discovery,
        id_token,
        request,
        state.cfg.upstream().outbound_allowed_domains(),
    );
    let created_at_epoch_secs = match now_epoch_secs() {
        Ok(now) => now,
        Err(_) => {
            record_upstream_callback_session_failure_audit(
                &state.db_pool,
                request,
                &user.user_id,
                request_id,
                "server_clock_unavailable",
            )
            .await;
            return clock_error_response(state.issuer.as_str());
        }
    };
    let Some(session_times) =
        AuthSessionTimes::from_upstream(created_at_epoch_secs, user.auth_time)
    else {
        record_upstream_callback_session_failure_audit(
            &state.db_pool,
            request,
            &user.user_id,
            request_id,
            "upstream_auth_time_invalid",
        )
        .await;
        return json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "invalid_grant",
            Some("upstream id_token auth_time is invalid"),
            state.issuer.as_str(),
        );
    };
    let sid = match create_auth_session_or_error_response_async(
        &state.browser_auth.auth_sessions,
        state.issuer.as_str(),
        user.user_id.clone(),
        session_times,
        acr,
        request.claim_release_policy.clone(),
        upstream_logout,
    )
    .await
    {
        Ok(sid) => sid,
        Err(response) => {
            record_upstream_callback_session_failure_audit(
                &state.db_pool,
                request,
                &user.user_id,
                request_id,
                "auth_session_store_unavailable",
            )
            .await;
            return response;
        }
    };
    let redirect_to = request.return_to.clone().unwrap_or_else(|| "/".to_string());
    let mut response = no_cache_redirect_response(&redirect_to);
    if let Ok(value) = HeaderValue::from_str(&build_session_set_cookie(
        &sid,
        state.browser_auth.auth_sessions.cookie_ttl_secs(),
    )) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

pub(super) async fn upstream_callback(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Path(connection): Path<String>,
    Query(params): Query<UpstreamCallbackQuery>,
) -> Response {
    let issuer_base = state.issuer.as_str();
    let request_id = request_id_from_headers(&headers);
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }
    if let Err(resp) = enforce_no_credentials_in_callback_uri(&uri, issuer_base) {
        return resp;
    }
    if let Some(response) = handle_upstream_callback_error(&state, &params, issuer_base).await {
        return response;
    }

    let mut callback = match consume_upstream_callback_context(&state, &params, issuer_base).await {
        Ok(callback) => callback,
        Err(response) => return response,
    };
    if let Err(response) =
        validate_upstream_callback_issuer(&params, &callback.request, issuer_base)
    {
        return response;
    }
    if let Err(response) = validate_and_hydrate_upstream_callback_connection(
        &state.db_pool,
        &mut callback.request,
        &connection,
        issuer_base,
    )
    .await
    {
        return response;
    }

    let exchange = match perform_upstream_callback_exchange(
        &state,
        &callback.request,
        &callback.code,
        issuer_base,
    )
    .await
    {
        Ok(exchange) => exchange,
        Err(response) => return response,
    };
    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return json_error_with_iss(
                StatusCode::BAD_GATEWAY,
                "server_error",
                Some("failed to begin upstream callback transaction"),
                issuer_base,
            );
        }
    };
    let user = match resolve_upstream_callback_user(
        &mut tx,
        &callback.request,
        &exchange,
        issuer_base,
        &request_id,
    )
    .await
    {
        Ok(user) => user,
        Err(response) => return response,
    };

    if let Err(response) = record_upstream_callback_audit(
        &mut tx,
        &callback.request,
        &user.user_id,
        issuer_base,
        &request_id,
    )
    .await
    {
        return response;
    }
    if let Err(response) =
        persist_upstream_callback_refresh_token(&mut tx, &callback.request, &exchange, issuer_base)
            .await
    {
        return response;
    }
    if let Err(response) = sync_upstream_callback_projection(
        &mut tx,
        &callback.request,
        user.local_end_user_id,
        &exchange.id_token,
        issuer_base,
    )
    .await
    {
        return response;
    }
    if tx.commit().await.is_err() {
        return json_error_with_iss(
            StatusCode::BAD_GATEWAY,
            "server_error",
            Some("failed to commit upstream callback transaction"),
            issuer_base,
        );
    }
    finalize_upstream_callback_response(
        &state,
        &callback.request,
        &exchange.discovery,
        &exchange.id_token,
        &user,
        &request_id,
    )
    .await
}
