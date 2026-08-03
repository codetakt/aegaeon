use super::{error_response, management_internal_error, required_row_value};
use crate::management::types::{Client, ClientSecret};
use axum::{http::StatusCode, response::Response};
use sqlx::postgres::PgRow;
use uuid::Uuid;

pub(super) fn client_secret_auth_method_supported(method: &str) -> bool {
    let method = method.trim();
    method.eq_ignore_ascii_case("client_secret_basic")
        || method.eq_ignore_ascii_case("client_secret_post")
}

pub(super) fn client_accepts_client_secrets(client: &Client) -> bool {
    client
        .client_type
        .trim()
        .eq_ignore_ascii_case("CONFIDENTIAL")
        && client_secret_auth_method_supported(&client.token_endpoint_authentication_method)
}

pub(super) fn reject_client_secret_lifecycle_unsupported(request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "Client secrets can only be issued for CONFIDENTIAL clients using client_secret_basic or client_secret_post",
        None,
        Some(request_id),
    )
}

fn client_secret_from_row(row: &PgRow, request_id: &str) -> Result<ClientSecret, Response> {
    let message = "Failed to load client secret";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let client_id: Uuid = required_row_value(row, "client_id", request_id, message)?;
    let status: String = required_row_value(row, "status", request_id, message)?;
    let active_slot: Option<i16> = required_row_value(row, "active_slot", request_id, message)?;
    let active_slot = active_slot
        .map(u32::try_from)
        .transpose()
        .map_err(|_| management_internal_error(request_id, message))?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let expires_at: String = required_row_value(row, "expires_at", request_id, message)?;

    Ok(ClientSecret {
        id: id.to_string(),
        client_id: client_id.to_string(),
        status,
        active_slot,
        created_at,
        expires_at,
    })
}

pub(super) fn client_secret_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<ClientSecret, Response> {
    client_secret_from_row(row, request_id)
}

pub(super) fn client_secret_not_found(request_id: &str) -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "Client secret not found",
        None,
        Some(request_id),
    )
}
