mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use crate::management::types::CreateConnectionRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::create_connection_inner;

pub(in crate::web::management::connections) async fn create_connection(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Json(req): Json<CreateConnectionRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match create_connection_inner(pool, &params, &req, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::CREATED, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
