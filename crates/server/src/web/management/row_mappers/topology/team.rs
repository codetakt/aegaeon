use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::Team;

use super::super::super::required_row_value;

fn team_with_id_from_row(row: &PgRow, request_id: &str) -> Result<(Uuid, Team), Response> {
    let message = "Failed to read created team";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let name: String = required_row_value(row, "name", request_id, message)?;
    let slug: Option<String> = required_row_value(row, "slug", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let updated_at: String = required_row_value(row, "updated_at", request_id, message)?;
    Ok((
        id,
        Team {
            id: id.to_string(),
            name,
            slug,
            created_at,
            updated_at,
        },
    ))
}

pub(in crate::web::management) fn team_with_id_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<(Uuid, Team), Response> {
    team_with_id_from_row(row, request_id)
}

pub(in crate::web::management) fn team_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<Team, Response> {
    team_with_id_from_row(row, request_id).map(|(_, team)| team)
}
