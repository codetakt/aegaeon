mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
    RuntimeClientMutationSync, TeamEnvironmentClientPath,
};
use crate::management::types::UpdateClientRequest;
use crate::web::management::{enforce_if_match, get_client_inner};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::{update_client_workflow, UpdateClientWorkflowInput};

pub(in crate::web::management::clients) async fn update_client(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentClientPath>,
    Json(req): Json<UpdateClientRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let (team_id, environment_id, client_id) = match path.ids(&ctx.request_id) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };
    let current = match get_client_inner(
        pool,
        team_id,
        environment_id,
        client_id,
        &session,
        &ctx.request_id,
    )
    .await
    {
        Ok(current) => current,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }
    match update_client_workflow(UpdateClientWorkflowInput {
        pool,
        runtime_sync: RuntimeClientMutationSync::from_state(&state),
        team_id,
        environment_id,
        client_id,
        req: &req,
        session: &session,
        request_id: &ctx.request_id,
    })
    .await
    {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
