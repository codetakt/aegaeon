use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::Client;

use super::super::required_row_value;

fn client_from_row(row: &PgRow, request_id: &str) -> Result<Client, Response> {
    let message = "Failed to load client";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let oauth_profile_id: Option<Uuid> =
        required_row_value(row, "oauth_profile_id", request_id, message)?;
    let client_identifier: String =
        required_row_value(row, "client_identifier", request_id, message)?;
    let name: String = required_row_value(row, "name", request_id, message)?;
    let client_type: String = required_row_value(row, "client_type", request_id, message)?;
    let redirect_uris: Vec<String> = required_row_value(row, "redirect_uris", request_id, message)?;
    let allowed_grant_types: Vec<String> =
        required_row_value(row, "allowed_grant_types", request_id, message)?;
    let allowed_scopes: Vec<String> =
        required_row_value(row, "allowed_scopes", request_id, message)?;
    let token_endpoint_authentication_method: String = required_row_value(
        row,
        "token_endpoint_authentication_method",
        request_id,
        message,
    )?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let updated_at: String = required_row_value(row, "updated_at", request_id, message)?;

    Ok(Client {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        oauth_profile_id: oauth_profile_id.map(|value| value.to_string()),
        client_identifier,
        name,
        client_type,
        redirect_uris,
        allowed_grant_types,
        allowed_scopes,
        token_endpoint_authentication_method,
        created_at,
        updated_at,
    })
}

pub(in crate::web::management) fn client_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<Client, Response> {
    client_from_row(row, request_id)
}
