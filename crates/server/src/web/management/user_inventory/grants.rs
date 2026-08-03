mod workflows;

use super::super::{
    paginate_in_memory, require_user_id_param, require_user_management_context, AppState,
    PaginationQuery, RequestContext,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflows::{list_user_grants_inner, revoke_user_grant_inner};

pub(super) async fn list_user_grants(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserPath>,
    Query(query): Query<PaginationQuery>,
) -> Response {
    let context =
        match require_user_management_context(&state, &headers, &params, &ctx.request_id).await {
            Ok(context) => context,
            Err(resp) => return resp,
        };
    let user_id = match require_user_id_param(&params, &ctx.request_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match list_user_grants_inner(&state, &context, user_id, &ctx.request_id).await {
        Ok(mut body) => match paginate_in_memory(body.grants, &query, &ctx.request_id) {
            Ok((items, page_info)) => {
                body.grants = items;
                body.page_info = page_info;
                (StatusCode::OK, Json(body)).into_response()
            }
            Err(resp) => resp,
        },
        Err(resp) => resp,
    }
}

pub(super) async fn revoke_user_grant(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserGrantPath>,
) -> Response {
    let context =
        match require_user_management_context(&state, &headers, &params, &ctx.request_id).await {
            Ok(context) => context,
            Err(resp) => return resp,
        };
    let (_, _, user_id, grant_id) = match params.ids(&ctx.request_id) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };

    match revoke_user_grant_inner(&state, &context, user_id, &grant_id, &ctx.request_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}
