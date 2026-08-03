use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::Tenant;

use super::super::super::required_row_value;

fn tenant_from_row(row: &PgRow, team_id: Uuid, request_id: &str) -> Result<Tenant, Response> {
    let message = "Failed to read tenant row";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let slug: String = required_row_value(row, "slug", request_id, message)?;
    let name: String = required_row_value(row, "name", request_id, message)?;
    let region: String = required_row_value(row, "region", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let updated_at: String = required_row_value(row, "updated_at", request_id, message)?;
    Ok(Tenant {
        id: id.to_string(),
        team_id: team_id.to_string(),
        slug,
        name,
        region,
        created_at,
        updated_at,
    })
}

pub(in crate::web::management) fn tenant_response_from_row(
    row: &PgRow,
    team_id: Uuid,
    request_id: &str,
) -> Result<Tenant, Response> {
    tenant_from_row(row, team_id, request_id)
}
