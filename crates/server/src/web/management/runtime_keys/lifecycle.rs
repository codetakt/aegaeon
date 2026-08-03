mod workflows;

use super::super::{
    management_db_pool, require_human_management_session_async, AppState, RequestContext,
};
use crate::management::types::{ActivateRuntimeKeyRequest, ConfigurationTransactionRequest};
use crate::web::management::{
    RuntimeCriticalMutationGuard, TeamEnvironmentPath, TeamEnvironmentRuntimeKeyPath,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management) use workflows::{
    activate_next_runtime_key_inner, revoke_runtime_key_inner,
};

pub(super) async fn activate_next_runtime_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
    Json(req): Json<ActivateRuntimeKeyRequest>,
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
    match activate_next_runtime_key_inner(pool, &path, &req, &session, &ctx.request_id).await {
        Ok(body) => {
            RuntimeCriticalMutationGuard::from_state(&state)
                .request_restart_if_current_issuer_was_mutated(
                    &body.environment.issuer_host,
                    &ctx.request_id,
                    "runtime_key_activate_next",
                );
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(resp) => resp,
    }
}

pub(super) async fn revoke_runtime_key(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentRuntimeKeyPath>,
    Json(req): Json<ConfigurationTransactionRequest>,
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
    match revoke_runtime_key_inner(pool, &path, &req, &session, &ctx.request_id).await {
        Ok(body) => {
            RuntimeCriticalMutationGuard::from_state(&state)
                .request_restart_if_current_issuer_was_mutated(
                    &body.environment.issuer_host,
                    &ctx.request_id,
                    "runtime_key_revoke",
                );
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(resp) => resp,
    }
}
