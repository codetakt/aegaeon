use crate::management::types::ListClientsResponse;
use crate::web::management::client_store::{client_from_row_result, list_client_rows};
use crate::web::management::{
    ensure_team_visible, keyset_cursor_from_row, page_info_for_keyset_rows, pagination_limit,
    state::ManagementSession, timestamp_uuid_pagination_params, PaginationQuery,
};
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn list_clients_inner(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    query: &PaginationQuery,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListClientsResponse, Response> {
    ensure_team_visible(pool, team_id, session, request_id).await?;

    let pagination = timestamp_uuid_pagination_params(query, request_id)?;
    let limit = pagination.limit;
    let rows = list_client_rows(
        pool,
        team_id,
        environment_id,
        pagination.cursor_value(0),
        pagination.cursor_value(1),
        limit.saturating_add(1),
        request_id,
    )
    .await?;
    let clients = rows
        .iter()
        .take(pagination_limit(limit))
        .map(|row| client_from_row_result(row, request_id))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ListClientsResponse {
        clients,
        page_info: page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], request_id)
        })?,
    })
}
