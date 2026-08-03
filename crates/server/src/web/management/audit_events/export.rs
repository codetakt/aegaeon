mod response;
mod workflow;

use super::super::audit_query::AuditExportQuery;
use super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use super::scope::{require_environment_audit_scope, require_team_audit_scope};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
    Extension,
};
use workflow::export_audit_events_inner;

pub(super) async fn export_team_audit_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamPath>,
    Query(query): Query<AuditExportQuery>,
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
        "Insufficient permissions; audit export requires OWNER, ADMINISTRATOR, or AUDITOR role",
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    match export_audit_events_inner(
        pool,
        scope,
        query,
        "attachment; filename=\"audit-events.csv\"",
        &ctx.request_id,
    )
    .await
    {
        Ok(resp) | Err(resp) => resp,
    }
}

pub(super) async fn export_environment_audit_events(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Query(query): Query<AuditExportQuery>,
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
        "Insufficient permissions; audit export requires OWNER, ADMINISTRATOR, or AUDITOR role",
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    match export_audit_events_inner(
        pool,
        scope,
        query,
        "attachment; filename=\"environment-audit-events.csv\"",
        &ctx.request_id,
    )
    .await
    {
        Ok(resp) | Err(resp) => resp,
    }
}
