mod workflow;

use super::super::super::{
    management_db_pool, paginate_in_memory, require_management_session_async, AppState,
    PaginationQuery, RequestContext, TeamPath,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::list_api_keys_inner;

pub(in crate::web::management::api_keys) async fn list_api_keys(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamPath>,
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
    let team_id = match path.id(&ctx.request_id) {
        Ok(team_id) => team_id,
        Err(resp) => return resp,
    };
    match list_api_keys_inner(pool, team_id, &session, &ctx.request_id).await {
        Ok(mut body) => match paginate_in_memory(body.api_keys, &query, &ctx.request_id) {
            Ok((items, page_info)) => {
                body.api_keys = items;
                body.page_info = page_info;
                (StatusCode::OK, Json(body)).into_response()
            }
            Err(resp) => resp,
        },
        Err(resp) => resp,
    }
}
