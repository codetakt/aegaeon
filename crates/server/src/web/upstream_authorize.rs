use super::request_admission::enforce_no_credentials_in_uri;
use super::{transport_rejection, AppState};
use axum::{
    extract::{ConnectInfo, OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use std::net::SocketAddr;

mod connection;
pub(super) mod context;
pub(super) mod discovery;
pub(super) mod flow;
pub(super) mod input;
mod profile;

#[cfg(test)]
pub(super) use connection::{upstream_authorize_auth_material, UpstreamConnection};
use context::{load_upstream_authorize_context, UpstreamAuthorizeContext};
use discovery::fetch_upstream_authorize_discovery_with;
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
    complete_upstream_authorize_with(
        &state,
        issuer_base,
        &connection_id,
        &context,
        &input,
        |anchors, now| {
            super::upstream_metadata::acquire_upstream_federation_chain(
                &state,
                &context.issuer,
                anchors,
                now,
            )
        },
    )
    .await
}

// Shared post-context workflow keeps metadata refusal before state and redirect.
// Only Federation acquisition is replaceable; signed admission remains mandatory.
pub(in crate::web) async fn complete_upstream_authorize_with<F, Fut>(
    state: &AppState,
    issuer_base: &str,
    connection_id: &str,
    context: &UpstreamAuthorizeContext,
    input: &UpstreamAuthorizeInput,
    acquire: F,
) -> Response
where
    F: FnMut(Vec<crate::federation::TrustAnchor>, i64) -> Fut,
    Fut: std::future::Future<
        Output = Result<crate::federation::ResolvedTrustChain, crate::federation::FederationError>,
    >,
{
    let discovery =
        match fetch_upstream_authorize_discovery_with(state, issuer_base, context, input, acquire)
            .await
        {
            Ok(discovery) => discovery,
            Err(resp) => return resp,
        };
    let flow = match store_upstream_authorize_request(
        state,
        connection_id,
        input,
        context,
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
        input,
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
