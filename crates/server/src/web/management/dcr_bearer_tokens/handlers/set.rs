use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

use crate::management::types::SetDcrBearerTokenRequest;
use crate::web::management::{
    enforce_if_match, management_db_pool, require_environment_lifecycle_scope_with_issuer_by_ids,
    require_human_management_session_async, AppState, RequestContext, RuntimeCriticalMutationGuard,
    TeamEnvironmentPath,
};

use super::super::{
    load_dcr_bearer_token_status, set_dcr_bearer_token_inner, validate_dcr_bearer_token,
};

pub(in crate::web::management::dcr_bearer_tokens::handlers) async fn set_dcr_bearer_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(path): Path<TeamEnvironmentPath>,
    Json(req): Json<SetDcrBearerTokenRequest>,
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
    let current = match load_dcr_bearer_token_status(pool, environment_id, &ctx.request_id).await {
        Ok(current) => current,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }
    let token = match validate_dcr_bearer_token(&req.token, &ctx.request_id) {
        Ok(token) => token,
        Err(resp) => return resp,
    };

    match set_dcr_bearer_token_inner(pool, scope, &session, &ctx.request_id, token).await {
        Ok(status) => {
            RuntimeCriticalMutationGuard::from_state(&state)
                .request_restart_if_current_issuer_was_mutated(
                    &issuer_host,
                    &ctx.request_id,
                    "dcr_bearer_token_set",
                );
            (StatusCode::OK, Json(status)).into_response()
        }
        Err(resp) => resp,
    }
}
