mod workflow;

pub(in crate::web::management) use workflow::{
    create_runtime_key_inner, ensure_runtime_key_algorithm_allowed_by_policy,
};

use super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext,
};
use crate::management::types::CreateRuntimeKeyRequest;
use crate::web::management::{RuntimeCriticalMutationGuard, TeamEnvironmentPath};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(super) async fn create_runtime_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
    Json(req): Json<CreateRuntimeKeyRequest>,
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
    match create_runtime_key_inner(pool, &path, &req, &session, &ctx.request_id).await {
        Ok(body) => {
            if body.runtime_key.status == "ACTIVE" {
                RuntimeCriticalMutationGuard::from_state(&state)
                    .request_restart_if_current_issuer_was_mutated(
                        &body.environment.issuer_host,
                        &ctx.request_id,
                        "runtime_key_create_active",
                    );
            }
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(resp) => resp,
    }
}
