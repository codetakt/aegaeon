mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use workflow::delete_federation_trust_anchor_inner;

pub(in crate::web::management::federation) async fn delete_federation_trust_anchor(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentTrustAnchorPath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };

    match delete_federation_trust_anchor_inner(pool, &params, &session, &ctx.request_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}
