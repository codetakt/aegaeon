use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};

use crate::web::management::{
    management_db_pool, require_environment_lifecycle_scope_with_issuer_by_ids,
    require_human_management_session_async, AppState, RequestContext, RuntimeCriticalMutationGuard,
    TeamEnvironmentPath,
};

use super::super::delete_dcr_bearer_token_inner;

pub(in crate::web::management::dcr_bearer_tokens::handlers) async fn delete_dcr_bearer_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
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
    let (team_id, environment_id) = match path.ids(&ctx.request_id) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };
    let scoped_issuer = match require_environment_lifecycle_scope_with_issuer_by_ids(
        pool,
        team_id,
        environment_id,
        &session,
        &ctx.request_id,
        "Insufficient permissions for DCR bearer token operations",
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };
    let scope = scoped_issuer.scope;
    let issuer_host = scoped_issuer.issuer_host;

    match delete_dcr_bearer_token_inner(pool, scope, &session, &ctx.request_id).await {
        Ok(()) => {
            RuntimeCriticalMutationGuard::from_state(&state)
                .request_restart_if_current_issuer_was_mutated(
                    &issuer_host,
                    &ctx.request_id,
                    "dcr_bearer_token_delete",
                );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(resp) => resp,
    }
}
