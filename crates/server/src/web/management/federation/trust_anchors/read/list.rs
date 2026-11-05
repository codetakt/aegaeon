use super::super::super::super::{
    collect_page_rows_result, ensure_environment_visible, keyset_cursor_from_row,
    management_db_pool, page_info_for_keyset_rows, parse_team_environment_scope,
    require_management_session_async, timestamp_uuid_pagination_params,
    trust_anchor_from_row_result, AppState, PaginationQuery, RequestContext,
};
use crate::management::types::ListFederationTrustAnchorsResponse;
use crate::web::management::http_errors::management_database_error as database_error;
use crate::web::management::request_support::owned::reads;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management::federation) async fn list_federation_trust_anchors(
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

    let pagination = match timestamp_uuid_pagination_params(&query, &ctx.request_id) {
        Ok(params) => params,
        Err(resp) => return resp,
    };
    let limit = pagination.limit;

    let rows = match load_rows(pool, environment_id, &pagination, &ctx.request_id).await {
        Ok(rows) => rows,
        Err(response) => return response,
    };

    let trust_anchors = match collect_page_rows_result(&rows, limit, |row| {
        trust_anchor_from_row_result(row, &ctx.request_id)
    }) {
        Ok(trust_anchors) => trust_anchors,
        Err(resp) => return resp,
    };
    let body = ListFederationTrustAnchorsResponse {
        trust_anchors,
        page_info: match page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], &ctx.request_id)
        }) {
            Ok(page_info) => page_info,
            Err(resp) => return resp,
        },
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn load_rows(
    pool: &sqlx::PgPool,
    environment_id: uuid::Uuid,
    pagination: &crate::web::management::pagination::KeysetPagination,
    request_id: &str,
) -> Result<Vec<sqlx::postgres::PgRow>, Response> {
    reads::all(
        pool,
        sqlx::query(
            r#"
SELECT
  id,
  environment_id,
  entity_id,
  jwks,
  metadata_policy,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  id::text AS id_cursor,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.federation_trust_anchors
WHERE environment_id = $1
  AND ($2::timestamptz IS NULL OR (created_at, id) > ($2::timestamptz, $3::uuid))
ORDER BY created_at ASC, id ASC
LIMIT $4
        "#,
        )
        .bind(environment_id)
        .bind(pagination.cursor_value(0))
        .bind(pagination.cursor_value(1))
        .bind(pagination.limit.saturating_add(1)),
        request_id,
    )
    .await?
    .map_err(|error| database_error(request_id, &error, "Database query failed"))
}
