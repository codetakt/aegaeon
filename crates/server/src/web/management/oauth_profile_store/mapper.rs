use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::OAuthProfile;

use super::super::required_row_value;

pub(in crate::web::management) fn oauth_profile_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<OAuthProfile, Response> {
    let message = "Failed to load oauth profile";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let configuration_version_id: Uuid =
        required_row_value(row, "configuration_version_id", request_id, message)?;
    let name: String = required_row_value(row, "name", request_id, message)?;
    let description: Option<String> = required_row_value(row, "description", request_id, message)?;
    let profile_type: String = required_row_value(row, "profile_type", request_id, message)?;
    let is_default: bool = required_row_value(row, "is_default", request_id, message)?;
    let require_pkce: bool = required_row_value(row, "require_pkce", request_id, message)?;
    let require_state_parameter: bool =
        required_row_value(row, "require_state_parameter", request_id, message)?;
    let require_iss_parameter: bool =
        required_row_value(row, "require_iss_parameter", request_id, message)?;
    let sender_constrained: String =
        required_row_value(row, "sender_constrained", request_id, message)?;
    let enforce_refresh_sender_binding: bool =
        required_row_value(row, "enforce_refresh_sender_binding", request_id, message)?;
    let allowed_grant_types: Vec<String> =
        required_row_value(row, "allowed_grant_types", request_id, message)?;
    let token_endpoint_auth_methods_allowed: Vec<String> = required_row_value(
        row,
        "token_endpoint_auth_methods_allowed",
        request_id,
        message,
    )?;
    let expires_at: Option<String> = required_row_value(row, "expires_at", request_id, message)?;
    let status: String = required_row_value(row, "status", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let updated_at: String = required_row_value(row, "updated_at", request_id, message)?;

    Ok(OAuthProfile {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        configuration_version_id: configuration_version_id.to_string(),
        name,
        description,
        profile_type,
        is_default,
        require_pkce,
        require_state_parameter,
        require_iss_parameter,
        sender_constrained,
        enforce_refresh_sender_binding,
        allowed_grant_types,
        token_endpoint_auth_methods_allowed,
        expires_at,
        status,
        created_at,
        updated_at,
    })
}
