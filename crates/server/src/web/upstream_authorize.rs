use super::request_admission::enforce_no_credentials_in_uri;
use super::{transport_rejection, AppState};
use axum::{
    extract::{ConnectInfo, OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use std::net::SocketAddr;

mod connection;
mod context;
mod discovery;
mod flow;
mod input;
mod profile;

#[cfg(test)]
pub(super) use connection::{upstream_authorize_auth_material, UpstreamConnection};
use context::{load_upstream_authorize_context, UpstreamAuthorizeContext};
use discovery::fetch_upstream_authorize_discovery;
#[cfg(test)]
pub(super) use flow::build_upstream_redirect_uri;
use flow::{build_upstream_authorize_redirect_response, store_upstream_authorize_request};
use input::{parse_upstream_authorize_input, UpstreamAuthorizeInput, UpstreamAuthorizeQuery};

pub(super) async fn upstream_authorize(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Path(connection_id): Path<String>,
    Query(params): Query<UpstreamAuthorizeQuery>,
) -> Response {
    let issuer_base = state.issuer.as_str();
    if let Err(kind) = state.transport.enforce(Some(remote), &headers) {
        return transport_rejection(&state, kind);
    }
    if let Err(resp) = enforce_no_credentials_in_uri(&uri, issuer_base) {
        return resp;
    }
    let pool = &state.db_pool;
    let input = match parse_upstream_authorize_input(&state, params, issuer_base) {
        Ok(input) => input,
        Err(resp) => return resp,
    };
    let context =
        match load_upstream_authorize_context(&state, pool, issuer_base, &connection_id).await {
            Ok(context) => context,
            Err(resp) => return resp,
        };
    let discovery =
        match fetch_upstream_authorize_discovery(&state, issuer_base, &context, &input).await {
            Ok(discovery) => discovery,
            Err(resp) => return resp,
        };
    let flow = match store_upstream_authorize_request(
        &state,
        &connection_id,
        &input,
        &context,
        &discovery,
        issuer_base,
    )
    .await
    {
        Ok(flow) => flow,
        Err(resp) => return resp,
    };

    match build_upstream_authorize_redirect_response(
        issuer_base,
        &discovery,
        &context.connection.client_id,
        &input,
        &flow,
        matches!(
            context.active_logout_recovery_policy,
            Some(crate::upstream::UpstreamLogoutRecoveryPolicy::ForcePromptLogin)
        ),
    ) {
        Ok(response) => response,
        Err(resp) => resp,
    }
}
