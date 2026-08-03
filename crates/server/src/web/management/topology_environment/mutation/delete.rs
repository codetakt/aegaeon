use super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    management_db_pool, parse_team_environment_scope, require_human_management_session_async,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction, AppState,
    RequestContext, RuntimeCriticalMutationGuard,
};
use super::persistence::delete_environment_row;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};

pub(in crate::web::management) async fn delete_environment(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
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
    if let Err(resp) = require_team_lifecycle_role(
        pool,
        team_id,
        &session,
        &ctx.request_id,
        "Insufficient permissions for environment lifecycle operations",
    )
    .await
    {
        return resp;
    }

    let mut tx = match begin_management_transaction(pool, &ctx.request_id).await {
        Ok(tx) => tx,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        &session,
        &ctx.request_id,
        "Insufficient permissions for environment lifecycle operations",
    )
    .await
    {
        return resp;
    }

    match delete_environment_row(&mut tx, team_id, environment_id, &ctx.request_id).await {
        Ok(Some(issuer_host)) => {
            if let Err(resp) = commit_management_transaction(tx, &ctx.request_id).await {
                return resp;
            }
            RuntimeCriticalMutationGuard::from_state(&state)
                .request_restart_if_current_issuer_was_mutated(
                    &issuer_host,
                    &ctx.request_id,
                    "environment_delete",
                );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Environment not found",
            None,
            Some(ctx.request_id.as_str()),
        ),
        Err(resp) => resp,
    }
}
