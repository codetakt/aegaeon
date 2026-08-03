mod workflow;

use super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use crate::management::types::ClearFederationLogoutRecoveryIncidentRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::clear_federation_logout_recovery_incident_inner;

pub(super) async fn clear_federation_logout_recovery_incident(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentIncidentPath>,
    Json(req): Json<ClearFederationLogoutRecoveryIncidentRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };

    match clear_federation_logout_recovery_incident_inner(
        pool,
        &params,
        &req,
        &session,
        &ctx.request_id,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}
