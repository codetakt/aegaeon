use super::super::filters::account_link_list_filters;
use super::rows::{list_account_link_rows, load_account_link_subject_hash_candidates};
use crate::management::types::ListAccountLinksResponse;
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    account_link_from_row_result, collect_page_rows_result, ensure_environment_visible,
    keyset_cursor_from_row, normalize_account_link_upstream_subject_filter,
    page_info_for_keyset_rows, parse_team_environment_scope, timestamp_uuid_pagination_params,
    AccountLinkListQuery, PaginationQuery,
};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_account_links_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    query: &AccountLinkListQuery,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListAccountLinksResponse, Response> {
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    ensure_environment_visible(pool, team_id, environment_id, session, request_id).await?;

    let pagination = timestamp_uuid_pagination_params(
        &PaginationQuery {
            page_size: query.page_size,
            page_token: query.page_token.clone(),
        },
        request_id,
    )?;
    let limit = pagination.limit;
    let upstream_subject_hashes =
        match normalize_account_link_upstream_subject_filter(query.upstream_subject.as_deref()) {
            Some(upstream_subject) => Some(
                load_account_link_subject_hash_candidates(
                    pool,
                    environment_id,
                    &upstream_subject,
                    request_id,
                )
                .await?,
            ),
            None => None,
        };

    let rows = list_account_link_rows(
        pool,
        team_id,
        environment_id,
        &account_link_list_filters(query, upstream_subject_hashes),
        &pagination,
        request_id,
    )
    .await?;

    Ok(ListAccountLinksResponse {
        account_links: collect_page_rows_result(&rows, limit, |row| {
            account_link_from_row_result(row, request_id)
        })?,
        page_info: page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], request_id)
        })?,
    })
}
