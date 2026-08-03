mod workflow;

use super::super::super::audit_query::AuditEventListQuery;
use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use super::super::scope::{require_environment_audit_scope, require_team_audit_scope};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::list_audit_events_inner;

pub(in crate::web::management::audit_events) async fn list_team_audit_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamPath>,
    Query(query): Query<AuditEventListQuery>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let scope = match require_team_audit_scope(
        pool,
        &params,
        &session,
        &ctx.request_id,
        "Insufficient permissions; audit read requires OWNER, ADMINISTRATOR, or AUDITOR role",
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    match list_audit_events_inner(pool, scope, query, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}

pub(in crate::web::management::audit_events) async fn list_environment_audit_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Query(query): Query<AuditEventListQuery>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let scope = match require_environment_audit_scope(
        pool,
        &params,
        &session,
        &ctx.request_id,
        "Insufficient permissions; audit read requires OWNER, ADMINISTRATOR, or AUDITOR role",
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    match list_audit_events_inner(pool, scope, query, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
