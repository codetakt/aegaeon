mod workflow;

use super::super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext, TeamPath,
};
use crate::management::types::CreateApiKeyRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management::api_keys) async fn create_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamPath>,
    Json(req): Json<CreateApiKeyRequest>,
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
    let team_id = match path.id(&ctx.request_id) {
        Ok(team_id) => team_id,
        Err(resp) => return resp,
    };
    match workflow::create_api_key_inner(pool, team_id, &req, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::CREATED, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
