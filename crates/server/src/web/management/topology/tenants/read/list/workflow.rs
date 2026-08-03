use super::rows::list_tenant_rows;
use crate::management::types::ListTenantsResponse;
use crate::web::management::{
    collect_page_rows_result, ensure_team_visible, keyset_cursor_from_row,
    page_info_for_keyset_rows, parse_team_scope, state::ManagementSession,
    tenant_response_from_row, timestamp_uuid_pagination_params, PaginationQuery,
};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_tenants_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamPath,
    query: &PaginationQuery,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListTenantsResponse, Response> {
    let team_id = parse_team_scope(params, request_id)?;
    ensure_team_visible(pool, team_id, session, request_id).await?;

    let pagination = timestamp_uuid_pagination_params(query, request_id)?;
    let limit = pagination.limit;
    let rows = list_tenant_rows(
        pool,
        team_id,
        pagination.cursor_value(0),
        pagination.cursor_value(1),
        limit.saturating_add(1),
        request_id,
    )
    .await?;
    let tenants = collect_page_rows_result(&rows, limit, |row| {
        tenant_response_from_row(row, team_id, request_id)
    })?;

    Ok(ListTenantsResponse {
        tenants,
        page_info: page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], request_id)
        })?,
    })
}
