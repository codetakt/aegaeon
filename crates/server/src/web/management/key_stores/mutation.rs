mod workflow;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

use crate::management::types::UpdateKeyStoreRequest;

use super::super::{
    enforce_if_match, get_key_store_inner, management_db_pool,
    require_human_management_session_async, AppState, RequestContext,
};

pub(in crate::web::management) async fn update_key_store(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Json(req): Json<UpdateKeyStoreRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session =
        match require_human_management_session_async(&state, &headers, &ctx.request_id).await {
            Ok(session) => session,
            Err(resp) => return resp,
        };
    let current = match get_key_store_inner(pool, &params, &session, &ctx.request_id).await {
        Ok(current) => current,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }
    match workflow::update_key_store_inner(pool, &params, &req, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
