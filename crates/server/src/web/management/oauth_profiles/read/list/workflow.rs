use super::super::super::super::oauth_profile_store::{
    list_oauth_profile_rows, oauth_profile_from_row_result,
};
use super::super::super::super::{
    ensure_team_visible_as, keyset_cursor_from_row, load_management_configuration_policy,
    load_management_environment_record, management_environment_not_found, nonnegative_i64_to_usize,
    page_info_for_keyset_rows, parse_team_environment_scope,
    resolve_management_configuration_version, timestamp_uuid_pagination_params, PaginationQuery,
};
use super::super::super::query::OAuthProfileListQuery;
use crate::management::types::ListOAuthProfilesResponse;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_oauth_profiles_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    query: &OAuthProfileListQuery,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListOAuthProfilesResponse, Response> {
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    ensure_team_visible_as(
        pool,
        team_id,
        session,
        request_id,
        management_environment_not_found,
    )
    .await?;

    let environment =
        load_management_environment_record(pool, team_id, environment_id, request_id).await?;
    let configuration_version_id = resolve_management_configuration_version(
        query.configuration_version_id.as_deref(),
        environment.active_configuration_version_id,
        request_id,
    )?;
    load_management_configuration_policy(pool, &environment, configuration_version_id, request_id)
        .await?;

    let pagination = timestamp_uuid_pagination_params(
        &PaginationQuery {
            page_size: query.page_size,
            page_token: query.page_token.clone(),
        },
        request_id,
    )?;
    let limit = pagination.limit;
    let limit_usize = nonnegative_i64_to_usize(limit);
    let rows = list_oauth_profile_rows(
        pool,
        environment.scope.team,
        environment.scope.environment,
        configuration_version_id,
        &pagination,
        request_id,
    )
    .await?;
    let oauth_profiles = rows
        .iter()
        .take(limit_usize)
        .map(|row| oauth_profile_from_row_result(row, request_id))
        .collect::<Result<Vec<_>, _>>()?;
    let page_info = page_info_for_keyset_rows(&rows, limit, |row| {
        keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], request_id)
    })?;

    Ok(ListOAuthProfilesResponse {
        oauth_profiles,
        page_info,
    })
}
