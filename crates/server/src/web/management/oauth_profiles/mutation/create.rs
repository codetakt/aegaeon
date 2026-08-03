mod preparation;
mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use super::super::query::OAuthProfileListQuery;
use crate::management::types::CreateOAuthProfileRequest;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::create_oauth_profile_inner;

pub(in crate::web::management::oauth_profiles) async fn create_oauth_profile(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Query(query): Query<OAuthProfileListQuery>,
    Json(req): Json<CreateOAuthProfileRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };

    match create_oauth_profile_inner(pool, &params, &query, &req, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::CREATED, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
