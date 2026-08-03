use super::super::store::list_user_rows;
use crate::management::types::{ListUsersQuery, ListUsersResponse};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    collect_page_rows_result, ensure_environment_visible, keyset_cursor_from_row,
    page_info_for_keyset_rows, pagination_params_from_parts, parse_team_environment_scope,
    user_from_row_result,
};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_users_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    query: &ListUsersQuery,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListUsersResponse, Response> {
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    ensure_environment_visible(pool, team_id, environment_id, session, request_id).await?;

    let pagination =
        pagination_params_from_parts(query.page_size, query.page_token.clone(), request_id)?;
    let limit = pagination.limit;
    let rows = list_user_rows(
        pool,
        team_id,
        environment_id,
        matches!(query.include_deleted, Some(true)),
        &pagination,
        request_id,
    )
    .await?;

    Ok(ListUsersResponse {
        users: collect_page_rows_result(&rows, limit, |row| user_from_row_result(row, request_id))?,
        page_info: page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], request_id)
        })?,
    })
}
