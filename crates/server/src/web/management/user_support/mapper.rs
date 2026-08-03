use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::end_user_profiles;
use crate::management::types::{User, UserProfile};

use super::super::required_row_value;

pub(in crate::web::management) fn user_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<User, Response> {
    let message = "Failed to load user";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let subject: String = required_row_value(row, "subject", request_id, message)?;
    let email: Option<String> = required_row_value(row, "email", request_id, message)?;
    let status: String = required_row_value(row, "status", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let updated_at: String = required_row_value(row, "updated_at", request_id, message)?;

    Ok(User {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        subject,
        email,
        status,
        created_at,
        updated_at,
    })
}

pub(in crate::web::management) fn user_profile_from_record(
    record: end_user_profiles::EndUserProfileRecord,
) -> UserProfile {
    UserProfile {
        user_id: record.user_id,
        subject: record.subject,
        subject_policy: record.subject_policy,
        email: record.email,
        email_verified: record.email_verified,
        display_name: record.display_name,
        custom_claims: record.custom_claims,
        version: record.version,
        updated_at: record.updated_at,
    }
}
