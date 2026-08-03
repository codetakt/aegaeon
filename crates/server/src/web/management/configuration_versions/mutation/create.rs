mod workflow;

use super::super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext,
};
use crate::management::types::CreateConfigurationVersionRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::create_configuration_version_inner;

pub(in crate::web::management::configuration_versions) async fn create_configuration_version(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Json(req): Json<CreateConfigurationVersionRequest>,
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
    match create_configuration_version_inner(pool, &params, &session, &req, ctx.request_id.as_str())
        .await
    {
        Ok(configuration_version) => {
            (StatusCode::CREATED, Json(configuration_version)).into_response()
        }
        Err(resp) => resp,
    }
}
