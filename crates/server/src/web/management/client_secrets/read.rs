mod workflow;

use super::super::{
    management_db_pool, paginate_in_memory, require_management_session_async, AppState,
    PaginationQuery, RequestContext,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(super) async fn list_client_secrets(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentClientPath>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };

    match workflow::list_client_secrets_inner(pool, &params, &session, &ctx.request_id).await {
        Ok(mut body) => match paginate_in_memory(body.client_secrets, &query, &ctx.request_id) {
            Ok((items, page_info)) => {
                body.client_secrets = items;
                body.page_info = page_info;
                (StatusCode::OK, Json(body)).into_response()
            }
            Err(resp) => resp,
        },
        Err(resp) => resp,
    }
}
