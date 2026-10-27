use super::oauth_errors::no_cache_json_error_with_iss;
use super::upstream_logout_incidents::{
    hash_upstream_logout_secret, invalid_logout_relay_state_response,
    persisted_logout_incident_response_by_hash,
};
use super::upstream_logout_sessions::upstream_logout_relay_store_unavailable_response;
use super::{no_cache_redirect_response, request_id_from_headers, transport_rejection, AppState};
use crate::util;
use axum::{
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::Response,
};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Deserialize, Default)]
pub(super) struct UpstreamLogoutCallbackQuery {
    state: Option<String>,
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
