mod workflow;

use super::super::super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext,
};
use crate::management::types::CreateTeamRequest;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::create_team_inner;

pub(in crate::web::management::topology) async fn create_team(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Json(req): Json<CreateTeamRequest>,
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

    match create_team_inner(pool, &req, session.administrator_id, &ctx.request_id).await {
        Ok(team) => (StatusCode::CREATED, Json(team)).into_response(),
        Err(resp) => resp,
    }
}
