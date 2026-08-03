mod workflow;

use super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use crate::management::types::PreviewAccountLinkConflictRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::preview_account_link_conflict_inner;

pub(in crate::web::management) async fn preview_account_link_conflict(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Json(req): Json<PreviewAccountLinkConflictRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match preview_account_link_conflict_inner(pool, &params, &req, &session, &ctx.request_id).await
    {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
