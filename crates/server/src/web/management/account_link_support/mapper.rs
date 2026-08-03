use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::AccountLinkSummary;

use super::super::required_row_value;

pub(in crate::web::management) fn account_link_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<AccountLinkSummary, Response> {
    let message = "Failed to load account link";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let connection_id: Uuid = required_row_value(row, "connection_id", request_id, message)?;
    let connection_identifier: String =
        required_row_value(row, "connection_identifier", request_id, message)?;
    let connection_name: String = required_row_value(row, "connection_name", request_id, message)?;
    let upstream_issuer: String = required_row_value(row, "upstream_issuer", request_id, message)?;
    let end_user_id: Uuid = required_row_value(row, "end_user_id", request_id, message)?;
    let end_user_subject: String =
        required_row_value(row, "end_user_subject", request_id, message)?;
    let end_user_email: Option<String> =
        required_row_value(row, "end_user_email", request_id, message)?;
    let end_user_status: String = required_row_value(row, "end_user_status", request_id, message)?;
    let has_refresh_token: bool =
        required_row_value(row, "has_refresh_token", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let last_used_at: Option<String> =
        required_row_value(row, "last_used_at", request_id, message)?;

    Ok(AccountLinkSummary {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        connection_id: connection_id.to_string(),
        connection_identifier,
        connection_name,
        upstream_issuer,
        end_user_id: end_user_id.to_string(),
        end_user_subject,
        end_user_email,
        end_user_status,
        has_refresh_token,
        created_at,
        last_used_at,
    })
}

#[derive(Debug, Clone)]
pub(in crate::web::management) struct AccountLinkConnectionRecord {
    pub(in crate::web::management) connection_identifier: String,
    pub(in crate::web::management) name: String,
    pub(in crate::web::management) issuer_url: String,
}

pub(in crate::web::management) fn account_link_connection_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<AccountLinkConnectionRecord, Response> {
    let message = "Failed to load connection";
    let connection_identifier: String =
        required_row_value(row, "connection_identifier", request_id, message)?;
    let name: String = required_row_value(row, "name", request_id, message)?;
    let issuer_url: String = required_row_value(row, "issuer_url", request_id, message)?;

    Ok(AccountLinkConnectionRecord {
        connection_identifier,
        name,
        issuer_url,
    })
}
