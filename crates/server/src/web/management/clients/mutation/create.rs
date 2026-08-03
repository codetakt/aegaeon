mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
    RuntimeClientMutationSync, TeamEnvironmentPath,
};
use crate::management::types::CreateClientRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::create_client_workflow;

pub(in crate::web::management::clients) async fn create_client(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
    Json(req): Json<CreateClientRequest>,
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
    match create_client_workflow(
        pool,
        RuntimeClientMutationSync::from_state(&state),
        team_id,
        environment_id,
        &req,
        &session,
        &ctx.request_id,
    )
    .await
    {
        Ok(body) => (StatusCode::CREATED, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
