use super::super::super::configuration_version_store::load_environment_policy_document;
use super::super::super::{
    ensure_environment_visible, management_db_pool, parse_team_environment_scope,
    require_management_session_async, AppState, RequestContext,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    Extension,
};

pub(in crate::web::management::configuration_versions) async fn get_policies(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let (team_id, environment_id) = match parse_team_environment_scope(&params, &ctx.request_id) {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };
    if let Err(resp) =
        ensure_environment_visible(pool, team_id, environment_id, &session, &ctx.request_id).await
    {
        return resp;
    }

    let policy = match load_environment_policy_document(pool, environment_id, &ctx.request_id).await
    {
        Ok(policy) => policy,
        Err(resp) => return resp,
    };
    crate::web::management::etagged_json(policy, &ctx.request_id)
}
