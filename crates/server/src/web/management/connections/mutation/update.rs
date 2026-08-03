mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use crate::management::types::UpdateConnectionRequest;
use crate::web::management::{enforce_if_match, get_connection_inner};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::update_connection_inner;

pub(in crate::web::management::connections) async fn update_connection(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentConnectionPath>,
    Json(req): Json<UpdateConnectionRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let current = match get_connection_inner(pool, &params, &session, &ctx.request_id).await {
        Ok(current) => current,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }
    match update_connection_inner(pool, &params, &req, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
