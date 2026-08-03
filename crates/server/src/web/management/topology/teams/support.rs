use super::super::super::required_row_value;
use crate::management::types::Team;
use axum::response::Response;
use sqlx::{postgres::PgRow, Row};
use uuid::Uuid;

pub(super) fn parse_team_id_param(
    params: &crate::web::management::TeamPath,
    request_id: &str,
) -> Result<Uuid, Response> {
    params.id(request_id)
}

pub(super) fn team_from_management_row(row: &PgRow, request_id: &str) -> Result<Team, Response> {
    let team_id: Uuid = row.try_get("id").map_err(|_| {
        super::super::super::management_internal_error(request_id, "Failed to read team row")
    })?;
    let name: String = required_row_value(row, "name", request_id, "Failed to read team row")?;
    let slug: Option<String> =
        required_row_value(row, "slug", request_id, "Failed to read team row")?;
    let created_at: String =
        required_row_value(row, "created_at", request_id, "Failed to read team row")?;
    let updated_at: String =
        required_row_value(row, "updated_at", request_id, "Failed to read team row")?;

    Ok(Team {
        id: team_id.to_string(),
        name,
        slug,
        created_at,
        updated_at,
    })
}
