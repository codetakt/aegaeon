use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    Extension,
};

use super::super::{
    require_user_id_param, require_user_management_context, AppState, RequestContext,
};
use super::store::load_user_row_for_status;

pub(super) async fn get_user(
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
    match load_user_row_for_status(
        &context.pool,
        &context,
        user_id,
        "AND u.status <> 'DELETED'",
        "User not found",
        &ctx.request_id,
    )
    .await
    {
        Ok(user) => crate::web::management::etagged_json(user, &ctx.request_id),
        Err(resp) => resp,
    }
}
