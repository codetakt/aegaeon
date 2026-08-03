mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management::federation_logout_recovery) async fn get_federation_logout_recovery_incident(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentIncidentPath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };

    match workflow::get_federation_logout_recovery_incident_inner(
        pool,
        &params,
        &session,
        &ctx.request_id,
    )
    .await
    {
        Ok(incident) => (StatusCode::OK, Json(incident)).into_response(),
        Err(resp) => resp,
    }
}
