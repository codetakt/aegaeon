use super::super::super::configuration_version_store::configuration_version_from_row_result;
use super::super::super::{
    ensure_environment_visible, error_response, management_db_pool, parse_team_environment_scope,
    require_management_session_async, AppState, RequestContext,
};
use super::persistence::fetch_configuration_version_row;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management::configuration_versions) async fn get_configuration_version(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentConfigurationVersionPath>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let (team_id, environment_id) = match parse_team_environment_scope(&params, &ctx.request_id) {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };
    let configuration_version_id = match params.configuration_version_id(&ctx.request_id) {
        Ok(configuration_version_id) => configuration_version_id,
        Err(resp) => return resp,
    };
    if let Err(resp) =
        ensure_environment_visible(pool, team_id, environment_id, &session, &ctx.request_id).await
    {
        return resp;
    }

    let row = match fetch_configuration_version_row(
        pool,
        team_id,
        environment_id,
        configuration_version_id,
        &ctx.request_id,
    )
    .await
    {
        Ok(row) => row,
        Err(resp) => return resp,
    };

    let Some(row) = row else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Configuration version not found",
            None,
            Some(ctx.request_id.as_str()),
        );
    };

    let configuration_version = match configuration_version_from_row_result(&row, &ctx.request_id) {
        Ok(configuration_version) => configuration_version,
        Err(resp) => return resp,
    };
    (StatusCode::OK, Json(configuration_version)).into_response()
}
