use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    Extension,
};

use crate::web::management::{
    ensure_environment_visible, management_db_pool, require_management_session_async, AppState,
    RequestContext, TeamEnvironmentPath,
};

use super::super::load_dcr_bearer_token_status;

pub(in crate::web::management::dcr_bearer_tokens::handlers) async fn get_dcr_bearer_token_status(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
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
        Ok(scope) => scope,
        Err(resp) => return resp,
    };
    if let Err(resp) =
        ensure_environment_visible(pool, team_id, environment_id, &session, &ctx.request_id).await
    {
        return resp;
    }

    match load_dcr_bearer_token_status(pool, environment_id, &ctx.request_id).await {
        Ok(status) => crate::web::management::etagged_json(status, &ctx.request_id),
        Err(resp) => resp,
    }
}
