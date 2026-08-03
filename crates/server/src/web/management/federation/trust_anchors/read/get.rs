use super::super::super::super::federation_cache::{
    federation_trust_anchor_not_found, load_visible_federation_trust_anchor,
};
use super::super::super::super::{
    ensure_team_visible_as, management_db_pool, parse_team_environment_scope,
    require_management_session_async, AppState, RequestContext,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management::federation) async fn get_federation_trust_anchor(
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

    let (team_id, environment_id) = match parse_team_environment_scope(&params, &ctx.request_id) {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };
    let trust_anchor_id = match params.trust_anchor_id(&ctx.request_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if let Err(resp) = ensure_team_visible_as(
        pool,
        team_id,
        &session,
        &ctx.request_id,
        federation_trust_anchor_not_found,
    )
    .await
    {
        return resp;
    }

    let trust_anchor = match load_visible_federation_trust_anchor(
        pool,
        team_id,
        trust_anchor_id,
        environment_id,
        &ctx.request_id,
    )
    .await
    {
        Ok(trust_anchor) => trust_anchor,
        Err(resp) => return resp,
    };

    (StatusCode::OK, Json(trust_anchor)).into_response()
}
