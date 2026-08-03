mod persistence;
mod rate_limit;
mod workflow;

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use std::net::SocketAddr;

use crate::management::types::BootstrapOwnerRequest;

use super::super::{management_db_pool, AppState, RequestContext};
use rate_limit::enforce_bootstrap_rate_limit;
use workflow::bootstrap_owner_inner;

pub(super) async fn bootstrap_owner(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Json(req): Json<BootstrapOwnerRequest>,
) -> Response {
    if let Err(resp) =
        enforce_bootstrap_rate_limit(&state, remote, &headers, &req, &ctx.request_id).await
    {
        return resp;
    }

    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };

    match bootstrap_owner_inner(pool, state.management.cfg.as_ref(), &req, &ctx.request_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}
