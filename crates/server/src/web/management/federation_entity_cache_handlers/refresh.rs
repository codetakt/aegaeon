mod workflow;

use crate::web::management::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
    TeamEnvironmentEntityCachePath,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::refresh_federation_entity_cache_entry_inner;

pub(in crate::web::management) async fn refresh_federation_entity_cache_entry(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<TeamEnvironmentEntityCachePath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match refresh_federation_entity_cache_entry_inner(
        pool,
        &params,
        &session,
        state.federation.cache_config.entity_cache_ttl,
        state
            .federation
            .cache_config
            .outbound_allowed_domains
            .clone(),
        ctx.request_id.as_str(),
    )
    .await
    {
        Ok(refreshed) => (StatusCode::OK, Json(refreshed)).into_response(),
        Err(resp) => resp,
    }
}
