use super::rows::list_team_rows;
use crate::management::types::ApiKeyCapability;
use crate::management::types::ListTeamsResponse;
use crate::web::management::{
    collect_page_rows_result, forbidden, keyset_cursor_from_row, page_info_for_keyset_rows,
    state::ManagementSession, team_from_row_result, timestamp_uuid_pagination_params,
    PaginationQuery,
};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_teams_inner(
    pool: &PgPool,
    query: &PaginationQuery,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ListTeamsResponse, Response> {
    if !can_read_team_topology(session) {
        return Err(forbidden(
            "forbidden",
            "Insufficient API key capabilities for team topology read",
            request_id,
        ));
    }

    let pagination = timestamp_uuid_pagination_params(query, request_id)?;
    let limit = pagination.limit;
    let rows = list_team_rows(
        pool,
        session.administrator_id,
        pagination.cursor_value(0),
        pagination.cursor_value(1),
        limit.saturating_add(1),
        request_id,
    )
    .await?;
    let teams =
        collect_page_rows_result(&rows, limit, |row| team_from_row_result(row, request_id))?;

    Ok(ListTeamsResponse {
        teams,
        page_info: page_info_for_keyset_rows(&rows, limit, |row| {
            keyset_cursor_from_row(row, &["created_at_cursor", "id_cursor"], request_id)
        })?,
    })
}

fn can_read_team_topology(session: &ManagementSession) -> bool {
    session.is_human_session() || session.api_key_has_capability(ApiKeyCapability::Read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn api_key_session(capability: ApiKeyCapability) -> ManagementSession {
        ManagementSession::api_key(
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![capability],
        )
    }

    #[test]
    fn team_topology_read_allows_human_sessions() {
        let session = ManagementSession::human(Uuid::new_v4(), 1);

        assert!(can_read_team_topology(&session));
    }

    #[test]
    fn team_topology_read_allows_read_or_team_administration_api_keys() {
        assert!(can_read_team_topology(&api_key_session(
            ApiKeyCapability::Read
        )));
        assert!(can_read_team_topology(&api_key_session(
            ApiKeyCapability::TeamAdministration
        )));
    }

    #[test]
    fn team_topology_read_rejects_non_read_api_keys() {
        assert!(!can_read_team_topology(&api_key_session(
            ApiKeyCapability::AuditRead
        )));
    }
}
