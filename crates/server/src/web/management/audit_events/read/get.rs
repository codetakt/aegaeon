use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use super::super::scope::require_team_audit_scope;
use super::super::store::fetch_audit_event;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management::audit_events) async fn get_audit_event(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamAuditEventPath>,
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
    let (_, audit_event_id) = match params.ids(&ctx.request_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match fetch_audit_event(pool, scope, audit_event_id, &ctx.request_id).await {
        Ok(event) => (StatusCode::OK, Json(event)).into_response(),
        Err(resp) => resp,
    }
}
