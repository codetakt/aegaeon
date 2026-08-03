use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Extension,
};

use super::super::super::{
    error_response, load_user_identity, require_user_id_param, require_user_management_scope,
    user_profile_from_record, AppState, RequestContext,
};
use crate::end_user_profiles;

pub(in crate::web::management::users) async fn get_user_profile(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentUserPath>,
) -> Response {
    let (pool, _session, team_id, environment_id, _tenant_id) =
        match require_user_management_scope(&state, &headers, &params, &ctx.request_id).await {
            Ok(scope) => scope,
            Err(resp) => return resp,
        };
    let user_id = match require_user_id_param(&params, &ctx.request_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match load_user_identity(&pool, team_id, environment_id, user_id).await {
        Ok(Some((_subject, _email, status))) if status != "DELETED" => {}
        Ok(Some(_) | None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "User not found",
                None,
                Some(ctx.request_id.as_str()),
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Database query failed",
                None,
                Some(ctx.request_id.as_str()),
            );
        }
    }

    match end_user_profiles::load_user_profile(&pool, user_id).await {
        Ok(Some(profile)) => {
            crate::web::management::etagged_json(user_profile_from_record(profile), &ctx.request_id)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "User profile not found",
            None,
            Some(ctx.request_id.as_str()),
        ),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to load user profile",
            None,
            Some(ctx.request_id.as_str()),
        ),
    }
}
