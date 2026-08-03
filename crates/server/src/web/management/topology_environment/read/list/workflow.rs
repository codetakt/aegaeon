use super::rows::list_environment_rows;
use crate::management::types::ListEnvironmentsResponse;
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    collect_page_rows_result, ensure_tenant_visible, environment_from_scoped_row_result,
    keyset_cursor_from_row, page_info_for_keyset_rows, parse_team_tenant_scope,
    timestamp_uuid_pagination_params, PaginationQuery,
};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_environments_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamTenantPath,
    query: &PaginationQuery,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListEnvironmentsResponse, Response> {
    let (team_id, tenant_id) = parse_team_tenant_scope(params, request_id)?;
    ensure_tenant_visible(pool, team_id, tenant_id, session, request_id).await?;

    let pagination = timestamp_uuid_pagination_params(query, request_id)?;
    let limit = pagination.limit;
    let rows = list_environment_rows(
        pool,
        team_id,
        tenant_id,
        pagination.cursor_value(0),
        pagination.cursor_value(1),
        limit.saturating_add(1),
        request_id,
    )
    .await?;
    let environments = collect_page_rows_result(&rows, limit, |row| {
        environment_from_scoped_row_result(row, team_id, tenant_id, request_id)
    })?;

    Ok(ListEnvironmentsResponse {
        environments,
        page_info: page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], request_id)
        })?,
    })
}
