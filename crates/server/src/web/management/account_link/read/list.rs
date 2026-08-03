mod rows;
mod workflow;

use super::super::super::{
    management_db_pool, require_management_session_async, AccountLinkListQuery, AppState,
    RequestContext,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::list_account_links_inner;

#[cfg(test)]
pub(in crate::web::management) use rows::LIST_ACCOUNT_LINK_ROWS_SQL;

pub(in crate::web::management::account_link) async fn list_account_links(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Query(query): Query<AccountLinkListQuery>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    match list_account_links_inner(pool, &params, &query, &session, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
