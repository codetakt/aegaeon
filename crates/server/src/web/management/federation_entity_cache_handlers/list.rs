use crate::management::types::ListFederationEntityCacheResponse;
use crate::web::management::{
    collect_page_rows_result, ensure_environment_visible,
    federation_entity_cache_entry_from_row_result, keyset_cursor_from_row, management_db_pool,
    management_internal_error, page_info_for_keyset_rows, parse_team_environment_scope,
    require_management_session_async, timestamp_uuid_pagination_params, AppState, PaginationQuery,
    RequestContext, TeamEnvironmentPath,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management) async fn list_federation_entity_cache(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<TeamEnvironmentPath>,
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

    let pagination = match timestamp_uuid_pagination_params(&query, &ctx.request_id) {
        Ok(params) => params,
        Err(resp) => return resp,
    };
    let limit = pagination.limit;
    let limit_plus_one = limit.saturating_add(1);

    let Ok(rows) = sqlx::query(
        r#"
SELECT
  id,
  environment_id,
  entity_id,
  entity_configuration_jws,
  parsed_statement,
  to_char(fetched_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS fetched_at_cursor,
  id::text AS id_cursor,
  to_char(fetched_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS fetched_at,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
FROM aegaeon.federation_entity_cache
WHERE environment_id = $1
  AND ($2::timestamptz IS NULL OR (fetched_at, id) < ($2::timestamptz, $3::uuid))
ORDER BY fetched_at DESC, id DESC
LIMIT $4
        "#,
    )
    .bind(environment_id)
    .bind(pagination.cursor_value(0))
    .bind(pagination.cursor_value(1))
    .bind(limit_plus_one)
    .fetch_all(pool)
    .await
    else {
        return management_internal_error(&ctx.request_id, "Database query failed");
    };

    let entity_cache_entries = match collect_page_rows_result(&rows, limit, |row| {
        federation_entity_cache_entry_from_row_result(row, &ctx.request_id)
    }) {
        Ok(entity_cache_entries) => entity_cache_entries,
        Err(resp) => return resp,
    };
    let body = ListFederationEntityCacheResponse {
        entity_cache_entries,
        page_info: match page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["fetched_at_cursor", "id_cursor"], &ctx.request_id)
        }) {
            Ok(page_info) => page_info,
            Err(resp) => return resp,
        },
    };
    (StatusCode::OK, Json(body)).into_response()
}
