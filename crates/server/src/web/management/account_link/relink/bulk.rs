mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use crate::management::types::BulkRelinkAccountLinksRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::bulk_relink_account_links_inner;

pub(in crate::web::management::account_link) async fn bulk_relink_account_links(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Json(req): Json<BulkRelinkAccountLinksRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match bulk_relink_account_links_inner(pool, &params, &req, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
