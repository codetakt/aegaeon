use crate::management::types::ListFederationTrustChainsResponse;
use crate::web::management::{
    collect_page_rows_result, ensure_environment_visible,
    federation_trust_chain_entry_from_row_result, keyset_cursor_from_row, management_db_pool,
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

pub(in crate::web::management::federation) async fn list_federation_trust_chains(
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
  leaf_entity_id,
  anchor_entity_id,
  chain_jwts,
  to_char(resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS resolved_at_cursor,
  id::text AS id_cursor,
  to_char(resolved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS resolved_at,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
FROM aegaeon.federation_trust_chains
WHERE environment_id = $1
  AND ($2::timestamptz IS NULL OR (resolved_at, id) < ($2::timestamptz, $3::uuid))
ORDER BY resolved_at DESC, id DESC
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

    let trust_chains = match collect_page_rows_result(&rows, limit, |row| {
        federation_trust_chain_entry_from_row_result(row, &ctx.request_id)
    }) {
        Ok(trust_chains) => trust_chains,
        Err(resp) => return resp,
    };
    let body = ListFederationTrustChainsResponse {
        trust_chains,
        page_info: match page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["resolved_at_cursor", "id_cursor"], &ctx.request_id)
        }) {
            Ok(page_info) => page_info,
            Err(resp) => return resp,
        },
    };
    (StatusCode::OK, Json(body)).into_response()
}
