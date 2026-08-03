use super::super::super::{
    error_response, invalid_email_response, is_unique_violation, management_internal_error,
    normalize_email, normalize_required_subject, user_from_row_result, user_not_found,
    UserManagementContext,
};
use crate::management::types::{UpdateUserRequest, User};
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(in crate::web::management::users) struct UserUpdatePatch {
    subject: Option<String>,
    email: Option<String>,
    clear_email: bool,
}

pub(in crate::web::management) const UPDATE_USER_FIELDS_ROW_SQL: &str = r#"
UPDATE aegaeon.end_users u
SET
  subject = COALESCE($4, u.subject),
  email = CASE
    WHEN $5 THEN $6
    ELSE u.email
  END,
  updated_at = now()
FROM aegaeon.environments e
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.id = $1
  AND u.environment_id = $2
  AND u.environment_id = e.id
  AND u.status <> 'DELETED'
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
RETURNING
  u.id,
  u.environment_id,
  u.subject,
  u.email,
  u.status::text AS status,
  to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#;

pub(in crate::web::management::users) fn build_user_update_patch(
    body: &UpdateUserRequest,
    request_id: &str,
) -> Result<UserUpdatePatch, Response> {
    let subject = match body.subject.as_deref() {
        Some(raw) => Some(normalize_required_subject(raw, request_id)?),
        None => None,
    };
    let (email, clear_email) = match body.email.as_ref() {
        Some(Some(raw)) => (
            Some(normalize_email(raw).ok_or_else(|| invalid_email_response(request_id))?),
            false,
        ),
        Some(None) => (None, true),
        None => (None, false),
    };
    if subject.is_none() && email.is_none() && !clear_email {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "At least one field must be updated",
            None,
            Some(request_id),
        ));
    }

    Ok(UserUpdatePatch {
        subject,
        email,
        clear_email,
    })
}

pub(in crate::web::management::users) async fn update_user_fields_row(
    tx: &mut Transaction<'_, Postgres>,
    context: &UserManagementContext,
    user_id: Uuid,
    patch: &UserUpdatePatch,
    request_id: &str,
) -> Result<User, Response> {
    let row = sqlx::query(UPDATE_USER_FIELDS_ROW_SQL)
        .bind(user_id)
        .bind(context.environment_id)
        .bind(context.team_id)
        .bind(patch.subject.as_deref())
        .bind(patch.clear_email || patch.email.is_some())
        .bind(patch.email.as_deref())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|err| {
            if is_unique_violation(&err) {
                error_response(
                    StatusCode::CONFLICT,
                    "conflict",
                    "A user with that subject already exists",
                    None,
                    Some(request_id),
                )
            } else {
                management_internal_error(request_id, "Database query failed")
            }
        })?;
    let row = row.ok_or_else(|| user_not_found(request_id))?;

    user_from_row_result(&row, request_id)
}
