mod workflow;

use super::super::super::{
    require_token_id_param, require_user_id_param, require_user_management_context, AppState,
    RequestContext,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use workflow::revoke_user_recovery_token_inner;

pub(in crate::web::management::user_credentials) async fn revoke_user_recovery_token(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserTokenPath>,
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
    let token_id = match require_token_id_param(&params, &ctx.request_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match revoke_user_recovery_token_inner(&context, user_id, token_id, &ctx.request_id).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(resp) => resp,
    }
}
