mod workflow;
pub(in crate::web::management) use workflow::get_oauth_profile_inner;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    Extension,
};

pub(in crate::web::management::oauth_profiles) async fn get_oauth_profile(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentOAuthProfilePath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };

    match get_oauth_profile_inner(pool, &params, &session, &ctx.request_id).await {
        Ok(profile) => crate::web::management::etagged_json(profile, &ctx.request_id),
        Err(resp) => resp,
    }
}
