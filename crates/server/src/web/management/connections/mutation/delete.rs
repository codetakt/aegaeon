mod workflow;

use super::super::super::{
    base_configuration_version_id_from_header, management_db_pool,
    require_management_session_async, AppState, RequestContext,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use workflow::delete_connection_inner;

pub(in crate::web::management::connections) async fn delete_connection(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentConnectionPath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let base_configuration_version_id =
        match base_configuration_version_id_from_header(&headers, &ctx.request_id) {
            Ok(value) => value,
            Err(resp) => return resp,
        };

    match delete_connection_inner(
        pool,
        &params,
        base_configuration_version_id,
        &session,
        &ctx.request_id,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}
