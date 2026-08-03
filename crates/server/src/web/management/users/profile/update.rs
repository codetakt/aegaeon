mod workflow;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

use super::super::super::{
    enforce_if_match, require_user_id_param, require_user_management_context,
    user_profile_from_record, AppState, RequestContext,
};
use crate::end_user_profiles;
use crate::management::types::UpdateUserProfileRequest;
use workflow::update_user_profile_inner;

pub(in crate::web::management::users) async fn update_user_profile_handler(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserPath>,
    Json(body): Json<UpdateUserProfileRequest>,
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
    let current = match end_user_profiles::load_user_profile(&context.pool, user_id).await {
        Ok(Some(profile)) => user_profile_from_record(profile),
        Ok(None) => return super::super::super::user_profile_not_found(&ctx.request_id),
        Err(_) => {
            return super::super::super::management_internal_error(
                &ctx.request_id,
                "Failed to load user profile",
            )
        }
    };
    if let Err(resp) = enforce_if_match(&headers, &current, &ctx.request_id) {
        return resp;
    }

    match update_user_profile_inner(&context, user_id, body, &ctx.request_id).await {
        Ok(profile) => (StatusCode::OK, Json(profile)).into_response(),
        Err(resp) => resp,
    }
}
