mod workflow;

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::Response,
    Extension, Json,
};
use std::net::SocketAddr;

use crate::management::types::CreateSessionRequest;

use super::super::super::{AppState, RequestContext};
use workflow::create_authentication_session_response;

pub(in crate::web::management::core) async fn create_authentication_session(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Json(req): Json<CreateSessionRequest>,
) -> Response {
    create_authentication_session_response(&state, remote, &headers, &req, &ctx.request_id).await
}
