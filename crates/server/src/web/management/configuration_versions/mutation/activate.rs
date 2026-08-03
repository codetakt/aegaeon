mod workflow;

use super::super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext,
};
use crate::management::types::ActivateConfigurationVersionRequest;
use crate::web::management::RuntimeCriticalMutationGuard;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::activate_configuration_version_inner;

pub(in crate::web::management::configuration_versions) async fn activate_configuration_version(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentConfigurationVersionPath>,
    Json(req): Json<ActivateConfigurationVersionRequest>,
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
    match activate_configuration_version_inner(pool, &params, &req, &session, &ctx.request_id).await
    {
        Ok(response) => {
            RuntimeCriticalMutationGuard::from_state(&state)
                .request_restart_if_current_issuer_was_mutated(
                    &response.environment.issuer_host,
                    &ctx.request_id,
                    "configuration_version_activate",
                );
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(resp) => resp,
    }
}
