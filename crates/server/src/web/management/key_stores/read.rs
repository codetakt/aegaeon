mod workflow;
pub(in crate::web::management) use workflow::get_key_store_inner;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    Extension,
};

use super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};

pub(in crate::web::management) async fn get_key_store(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match get_key_store_inner(pool, &params, &session, &ctx.request_id).await {
        Ok(body) => crate::web::management::etagged_json(body, &ctx.request_id),
        Err(resp) => resp,
    }
}
