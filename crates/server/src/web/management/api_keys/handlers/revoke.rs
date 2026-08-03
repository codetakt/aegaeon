mod workflow;

use super::super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext,
    TeamApiKeyPath,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};

pub(in crate::web::management::api_keys) async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamApiKeyPath>,
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
    let (team_id, api_key_id) = match path.ids(&ctx.request_id) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };
    match workflow::revoke_api_key_inner(pool, team_id, api_key_id, &session, &ctx.request_id).await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}
