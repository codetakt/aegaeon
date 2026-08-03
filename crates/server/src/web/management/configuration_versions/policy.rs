mod workflow;

use super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext,
};
use crate::management::types::PolicyPatchRequest;
use crate::web::management::configuration_version_store::load_environment_policy_document;
use crate::web::management::RuntimeCriticalMutationGuard;
use crate::web::management::{
    enforce_if_match, ensure_environment_visible, parse_team_environment_scope,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::patch_policies_inner;

pub(super) async fn patch_policies(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Json(req): Json<PolicyPatchRequest>,
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
    let (team_id, environment_id) = match parse_team_environment_scope(&params, &ctx.request_id) {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };
    if let Err(resp) =
        ensure_environment_visible(pool, team_id, environment_id, &session, &ctx.request_id).await
    {
        return resp;
    }
    let current =
        match load_environment_policy_document(pool, environment_id, &ctx.request_id).await {
            Ok(current) => current,
            Err(resp) => return resp,
        };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }

    match patch_policies_inner(pool, &params, &session, &req, &ctx.request_id).await {
        Ok(response) => {
            RuntimeCriticalMutationGuard::from_state(&state)
                .request_restart_if_current_issuer_was_mutated(
                    &response.environment.issuer_host,
                    &ctx.request_id,
                    "configuration_policy_patch",
                );
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(resp) => resp,
    }
}
