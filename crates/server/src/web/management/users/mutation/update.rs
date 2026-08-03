mod workflow;

use super::super::super::{
    require_user_id_param, require_user_management_context, AppState, RequestContext,
};
use super::super::store::load_user_row_for_status;
use crate::management::types::UpdateUserRequest;
use crate::web::management::enforce_if_match;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::update_user_inner;

pub(in crate::web::management::users) async fn update_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserPath>,
    Json(body): Json<UpdateUserRequest>,
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
    let current = match load_user_row_for_status(
        &context.pool,
        &context,
        user_id,
        "AND u.status <> 'DELETED'",
        "User not found",
        &ctx.request_id,
    )
    .await
    {
        Ok(current) => current,
        Err(resp) => return resp,
    };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }

    match update_user_inner(&context, user_id, &body, &ctx.request_id).await {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(resp) => resp,
    }
}
