use axum::{http::StatusCode, response::Response};
use sqlx::{Executor, Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::User;

use super::super::super::super::{
    error_response, management_internal_error, user_from_row_result, ManagementEnvironmentScope,
};

#[cfg(test)]
pub(in crate::web::management) const LOAD_ACCOUNT_LINK_TARGET_USER_SQL: &str = r#"
SELECT
  u.id,
  u.environment_id,
  u.subject,
  u.email,
  u.status::text AS status,
  to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.end_users u
JOIN aegaeon.environments e ON e.id = u.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.id = $1
  AND u.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
        "#;

const LOAD_ACCOUNT_LINK_TARGET_USER_FOR_UPDATE_SQL: &str = r#"
SELECT
  u.id,
  u.environment_id,
  u.subject,
  u.email,
  u.status::text AS status,
  to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.end_users u
JOIN aegaeon.environments e ON e.id = u.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.id = $1
  AND u.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
FOR UPDATE OF u
        "#;

pub(in crate::web::management) async fn load_account_link_target_user_for_update(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    end_user_id: Uuid,
    request_id: &str,
) -> Result<User, Response> {
    load_account_link_target_user_with_sql(
        &mut **tx,
        LOAD_ACCOUNT_LINK_TARGET_USER_FOR_UPDATE_SQL,
        scope,
        end_user_id,
        request_id,
    )
    .await
}

async fn load_account_link_target_user_with_sql<'e, E>(
    executor: E,
    sql: &str,
    scope: ManagementEnvironmentScope,
    end_user_id: Uuid,
    request_id: &str,
) -> Result<User, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(sql)
        .bind(end_user_id)
        .bind(scope.environment)
        .bind(scope.team)
        .fetch_optional(executor)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "User not found",
                None,
                Some(request_id),
            )
        })?;

    user_from_row_result(&row, request_id)
}

pub(in crate::web::management) fn ensure_account_link_target_not_deleted(
    target_user: &User,
    request_id: &str,
    message: &str,
) -> Result<(), Response> {
    if target_user.status == "DELETED" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            message,
            None,
            Some(request_id),
        ));
    }

    Ok(())
}
