use super::workflows::{
    invalidate_user_sessions_inner, list_user_sessions_inner, revoke_user_session_inner,
};
use crate::web::management::{
    paginate_in_memory, require_user_id_param, require_user_management_context, AppState,
    PaginationQuery, RequestContext,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management::user_inventory) async fn list_user_sessions(
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

    match list_user_sessions_inner(&state, &context, user_id, &ctx.request_id).await {
        Ok(mut body) => match paginate_in_memory(body.sessions, &query, &ctx.request_id) {
            Ok((items, page_info)) => {
                body.sessions = items;
                body.page_info = page_info;
                (StatusCode::OK, Json(body)).into_response()
            }
            Err(resp) => resp,
        },
        Err(resp) => resp,
    }
}

pub(in crate::web::management::user_inventory) async fn revoke_user_session(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserSessionPath>,
) -> Response {
    let context =
        match require_user_management_context(&state, &headers, &params, &ctx.request_id).await {
            Ok(context) => context,
            Err(resp) => return resp,
        };
    let (_, _, user_id, session_inventory_id) = match params.ids(&ctx.request_id) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };

    match revoke_user_session_inner(
        &state,
        &context,
        user_id,
        &session_inventory_id,
        &ctx.request_id,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}

pub(in crate::web::management::user_inventory) async fn invalidate_user_sessions(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserPath>,
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

    match invalidate_user_sessions_inner(&state, &context, user_id, &ctx.request_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(resp) => resp,
    }
}
