mod workflow;

use super::super::super::{require_user_management_context, AppState, RequestContext};
use crate::management::types::CreateUserRequest;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::create_user_inner;

pub(in crate::web::management::users) async fn create_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Json(body): Json<CreateUserRequest>,
) -> Response {
    let context =
        match require_user_management_context(&state, &headers, &params, &ctx.request_id).await {
            Ok(context) => context,
            Err(resp) => return resp,
        };

    match create_user_inner(&context, &body, &ctx.request_id).await {
        Ok(user) => (StatusCode::CREATED, Json(user)).into_response(),
        Err(resp) => resp,
    }
}
