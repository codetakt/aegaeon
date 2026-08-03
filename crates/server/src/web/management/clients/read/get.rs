mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
    TeamEnvironmentClientPath,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    Extension,
};
pub(in crate::web::management) use workflow::get_client_inner;

pub(in crate::web::management::clients) async fn get_client(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentClientPath>,
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
    match get_client_inner(
        pool,
        team_id,
        environment_id,
        client_id,
        &session,
        &ctx.request_id,
    )
    .await
    {
        Ok(client) => crate::web::management::etagged_json(client, &ctx.request_id),
        Err(resp) => resp,
    }
}
