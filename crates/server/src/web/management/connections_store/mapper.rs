use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::Connection;

use super::super::{parse_uuid_param, required_row_value};

pub(in crate::web::management) fn connection_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<Connection, Response> {
    let message = "Failed to load connection";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let configuration_version_id: Uuid =
        required_row_value(row, "configuration_version_id", request_id, message)?;
    let oauth_profile_id: Option<Uuid> =
        required_row_value(row, "oauth_profile_id", request_id, message)?;
    let connection_identifier: String =
        required_row_value(row, "connection_identifier", request_id, message)?;
    let name: String = required_row_value(row, "name", request_id, message)?;
    let connection_type: String = required_row_value(row, "connection_type", request_id, message)?;
    let issuer_url: String = required_row_value(row, "issuer_url", request_id, message)?;
    let client_id: String = required_row_value(row, "client_id", request_id, message)?;
    let client_auth_method: String =
        required_row_value(row, "client_auth_method", request_id, message)?;
    let status: String = required_row_value(row, "status", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let updated_at: String = required_row_value(row, "updated_at", request_id, message)?;

    Ok(Connection {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        configuration_version_id: configuration_version_id.to_string(),
        oauth_profile_id: oauth_profile_id.map(|value| value.to_string()),
        connection_identifier,
        name,
        connection_type,
        issuer_url,
        client_id,
        client_auth_method,
        status,
        created_at,
        updated_at,
    })
}

pub(in crate::web::management) fn parse_connection_configuration_version_id(
    connection: &Connection,
    request_id: &str,
) -> Result<Uuid, Response> {
    parse_uuid_param(
        &connection.configuration_version_id,
        "configurationVersionId",
        request_id,
    )
}
