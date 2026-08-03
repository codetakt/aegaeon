mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use crate::management::types::RelinkAccountLinkRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::relink_account_link_inner;

pub(in crate::web::management::account_link) async fn relink_account_link(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentAccountLinkPath>,
    Json(req): Json<RelinkAccountLinkRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match relink_account_link_inner(pool, &params, &req, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
