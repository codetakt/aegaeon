use super::super::super::topology_support::parse_update_name;
use super::super::super::{
    begin_management_transaction, commit_management_transaction, environment_response_from_row,
    error_response, management_db_pool, parse_team_environment_scope,
    require_management_session_async, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction, AppState, RequestContext,
};
use super::persistence::update_environment_row;
use crate::management::types::UpdateEnvironmentRequest;
use crate::web::management::{enforce_if_match, get_environment_inner};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management) async fn update_environment(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Json(req): Json<UpdateEnvironmentRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let (team_id, environment_id) = match parse_team_environment_scope(&params, &ctx.request_id) {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };
    let current = match get_environment_inner(pool, &params, &session, &ctx.request_id).await {
        Ok(current) => current,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }
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
    let name = match parse_update_name(req.name.as_deref(), &ctx.request_id) {
        Ok(name) => name,
        Err(resp) => return resp,
    };

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

    let row = match update_environment_row(&mut tx, team_id, environment_id, &name, &ctx.request_id)
        .await
    {
        Ok(row) => row,
        Err(resp) => return resp,
    };
    let Some(row) = row else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Environment not found",
            None,
            Some(ctx.request_id.as_str()),
        );
    };

    let environment = match environment_response_from_row(&row, team_id, &ctx.request_id) {
        Ok(environment) => environment,
        Err(resp) => return resp,
    };
    if let Err(resp) = commit_management_transaction(tx, &ctx.request_id).await {
        return resp;
    }
    (StatusCode::OK, Json(environment)).into_response()
}
