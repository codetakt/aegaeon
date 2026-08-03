mod rows;
mod workflow;

use super::super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use crate::management::types::UpdateTeamRequest;
use crate::web::management::{enforce_if_match, get_team_inner};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::update_team_inner;

pub(in crate::web::management::topology) async fn update_team(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamPath>,
    Json(req): Json<UpdateTeamRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let current = match get_team_inner(pool, &params, &session, &ctx.request_id).await {
        Ok(current) => current,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }

    match update_team_inner(pool, &params, &req, &session, &ctx.request_id).await {
        Ok(team) => (StatusCode::OK, Json(team)).into_response(),
        Err(resp) => resp,
    }
}
