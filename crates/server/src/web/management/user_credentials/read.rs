use super::super::{
    load_managed_user_identity, require_user_id_param, require_user_management_context, AppState,
    RequestContext,
};
use super::responses::load_user_credentials_response;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(super) async fn get_user_credentials(
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

    if let Err(resp) = load_managed_user_identity(
        &context.pool,
        context.team_id,
        context.environment_id,
        user_id,
        &ctx.request_id,
    )
    .await
    {
        return resp;
    }

    match load_user_credentials_response(&context.pool, user_id, &ctx.request_id).await {
        Ok(credentials) => (StatusCode::OK, Json(credentials)).into_response(),
        Err(resp) => resp,
    }
}
