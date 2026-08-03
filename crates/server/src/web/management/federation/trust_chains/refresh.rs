mod workflow;

use crate::web::management::{
    management_db_pool, require_management_session_async, AppState, RequestContext,
    TeamEnvironmentTrustChainPath,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::refresh_federation_trust_chain_inner;

pub(in crate::web::management::federation) async fn refresh_federation_trust_chain(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<TeamEnvironmentTrustChainPath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match refresh_federation_trust_chain_inner(
        pool,
        &params,
        &session,
        state.federation.cache_config.trust_chain_cache_ttl,
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
