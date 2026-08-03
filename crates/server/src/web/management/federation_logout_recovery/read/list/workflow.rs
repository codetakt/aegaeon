use crate::management::types::ListFederationLogoutRecoveryIncidentsResponse;
use crate::web::management::federation_logout_recovery::filters::{
    parse_federation_logout_recovery_incident_filters, FederationLogoutRecoveryIncidentListQuery,
};
use crate::web::management::federation_logout_recovery::store::{
    federation_logout_recovery_incident_from_row_result,
    list_federation_logout_recovery_incident_rows,
};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    collect_page_rows_result, keyset_cursor_from_row, load_management_environment_record,
    page_info_for_keyset_rows, parse_team_environment_scope, require_team_audit_read_access,
    timestamp_uuid_pagination_params, PaginationQuery,
};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_federation_logout_recovery_incidents_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    query: &FederationLogoutRecoveryIncidentListQuery,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListFederationLogoutRecoveryIncidentsResponse, Response> {
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    require_team_audit_read_access(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions; incident read requires audit read access",
    )
    .await?;

    let environment =
        load_management_environment_record(pool, team_id, environment_id, request_id).await?;
    let filters = parse_federation_logout_recovery_incident_filters(query, request_id)?;
    let pagination = timestamp_uuid_pagination_params(
        &PaginationQuery {
            page_size: query.page_size,
            page_token: query.page_token.clone(),
        },
        request_id,
    )?;
    let limit = pagination.limit;
    let rows = list_federation_logout_recovery_incident_rows(
        pool,
        environment.scope,
        &filters,
        pagination.cursor_value(0),
        pagination.cursor_value(1),
        limit.saturating_add(1),
        request_id,
    )
    .await?;
    let incidents = collect_page_rows_result(&rows, limit, |row| {
        federation_logout_recovery_incident_from_row_result(row, request_id)
    })?;

    Ok(ListFederationLogoutRecoveryIncidentsResponse {
        incidents,
        page_info: page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], request_id)
        })?,
    })
}
