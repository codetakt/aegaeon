mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, PaginationQuery,
    RequestContext, TeamEnvironmentPath,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::list_clients_inner;

pub(in crate::web::management::clients) async fn list_clients(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let (team_id, environment_id) = match path.ids(&ctx.request_id) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };
    match list_clients_inner(
        pool,
        team_id,
        environment_id,
        &query,
        &session,
        &ctx.request_id,
    )
    .await
    {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
