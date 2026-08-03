mod workflow;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

use super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use crate::management::types::ListUsersQuery;

pub(super) async fn list_users(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Query(query): Query<ListUsersQuery>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match workflow::list_users_inner(pool, &params, &query, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
