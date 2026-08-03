use super::super::super::configuration_version_store::configuration_version_summary_from_row_result;
use super::super::super::{
    collect_page_rows_result, ensure_environment_visible, integer_uuid_pagination_params,
    keyset_cursor_from_row, management_db_pool, page_info_for_keyset_rows,
    parse_team_environment_scope, require_management_session_async, AppState, PaginationQuery,
    RequestContext,
};
use super::persistence::fetch_configuration_version_rows;
use crate::management::types::ListConfigurationVersionsResponse;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management::configuration_versions) async fn list_configuration_versions(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamEnvironmentPath>,
    Query(query): Query<PaginationQuery>,
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
    if let Err(resp) =
        ensure_environment_visible(pool, team_id, environment_id, &session, &ctx.request_id).await
    {
        return resp;
    }

    let pagination = match integer_uuid_pagination_params(&query, &ctx.request_id) {
        Ok(params) => params,
        Err(resp) => return resp,
    };
    let limit = pagination.limit;
    let limit_plus_one = limit.saturating_add(1);

    let rows = match fetch_configuration_version_rows(
        pool,
        environment_id,
        pagination.cursor_value(0),
        pagination.cursor_value(1),
        limit_plus_one,
        &ctx.request_id,
    )
    .await
    {
        Ok(rows) => rows,
        Err(resp) => return resp,
    };

    let configuration_versions = match collect_page_rows_result(&rows, limit, |row| {
        configuration_version_summary_from_row_result(row, &ctx.request_id)
    }) {
        Ok(configuration_versions) => configuration_versions,
        Err(resp) => return resp,
    };
    let body = ListConfigurationVersionsResponse {
        configuration_versions,
        page_info: match page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(
                row,
                &["version_number_cursor", "id_cursor"],
                &ctx.request_id,
            )
        }) {
            Ok(page_info) => page_info,
            Err(resp) => return resp,
        },
    };
    (StatusCode::OK, Json(body)).into_response()
}
