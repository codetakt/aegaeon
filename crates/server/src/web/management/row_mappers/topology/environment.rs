use axum::response::Response;
use sqlx::{postgres::PgRow, Row};
use uuid::Uuid;

use crate::management::types::Environment;

use super::super::super::{management_internal_error, required_row_value};

fn environment_from_row(
    row: &PgRow,
    team_id: Uuid,
    tenant_id: Uuid,
    request_id: &str,
) -> Result<Environment, Response> {
    let message = "Failed to read environment row";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let name: String = required_row_value(row, "name", request_id, message)?;
    let slug: String = required_row_value(row, "slug", request_id, message)?;
    let issuer_host: String = required_row_value(row, "issuer_host", request_id, message)?;
    let issuer_url: String = required_row_value(row, "issuer_url", request_id, message)?;
    let active_configuration_version_id: Uuid =
        required_row_value(row, "active_configuration_version_id", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let updated_at: String = required_row_value(row, "updated_at", request_id, message)?;
    Ok(Environment {
        id: id.to_string(),
        team_id: team_id.to_string(),
        tenant_id: tenant_id.to_string(),
        name,
        slug,
        issuer_host,
        issuer_url,
        active_configuration_version_id: active_configuration_version_id.to_string(),
        created_at,
        updated_at,
    })
}

pub(in crate::web::management) fn environment_from_scoped_row_result(
    row: &PgRow,
    team_id: Uuid,
    tenant_id: Uuid,
    request_id: &str,
) -> Result<Environment, Response> {
    environment_from_row(row, team_id, tenant_id, request_id)
}

pub(in crate::web::management) fn environment_response_from_row(
    row: &PgRow,
    team_id: Uuid,
    request_id: &str,
) -> Result<Environment, Response> {
    let tenant_id: Uuid = row
        .try_get("tenant_id")
        .map_err(|_| management_internal_error(request_id, "Failed to read environment row"))?;
    environment_from_row(row, team_id, tenant_id, request_id)
}
