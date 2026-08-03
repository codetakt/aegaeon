use axum::response::Response;
use sqlx::{Executor, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::super::management_internal_error;
use super::super::errors::user_not_found;
use super::super::ManagedUserIdentity;

pub(in crate::web::management) const LOAD_USER_IDENTITY_SQL: &str = r"
SELECT
  u.subject,
  u.email,
  u.status::text AS status
FROM aegaeon.end_users u
JOIN aegaeon.environments e ON e.id = u.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.id = $1
  AND u.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
        ";

const LOAD_USER_IDENTITY_FOR_UPDATE_SQL: &str = r"
SELECT
  u.subject,
  u.email,
  u.status::text AS status
FROM aegaeon.end_users u
JOIN aegaeon.environments e ON e.id = u.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.id = $1
  AND u.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
FOR UPDATE OF u
        ";

pub(in crate::web::management) async fn load_user_identity(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    user_id: Uuid,
) -> Result<Option<(String, Option<String>, String)>, sqlx::Error> {
    load_user_identity_with_sql(
        pool,
        LOAD_USER_IDENTITY_SQL,
        team_id,
        environment_id,
        user_id,
    )
    .await
}

pub(in crate::web::management) async fn load_user_identity_for_update(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    user_id: Uuid,
) -> Result<Option<(String, Option<String>, String)>, sqlx::Error> {
    load_user_identity_with_sql(
        &mut **tx,
        LOAD_USER_IDENTITY_FOR_UPDATE_SQL,
        team_id,
        environment_id,
        user_id,
    )
    .await
}

async fn load_user_identity_with_sql<'e, E>(
    executor: E,
    sql: &str,
    team_id: Uuid,
    environment_id: Uuid,
    user_id: Uuid,
) -> Result<Option<(String, Option<String>, String)>, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(sql)
        .bind(user_id)
        .bind(environment_id)
        .bind(team_id)
        .fetch_optional(executor)
        .await?;

    row.as_ref()
        .map(|row| {
            Ok((
                row.try_get("subject")?,
                row.try_get("email")?,
                row.try_get("status")?,
            ))
        })
        .transpose()
}

pub(in crate::web::management) async fn load_managed_user_identity(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    user_id: Uuid,
    request_id: &str,
) -> Result<ManagedUserIdentity, Response> {
    match load_user_identity(pool, team_id, environment_id, user_id).await {
        Ok(Some((subject, email, status))) if status != "DELETED" => Ok(ManagedUserIdentity {
            subject,
            email,
            status,
        }),
        Ok(Some(_) | None) => Err(user_not_found(request_id)),
        Err(_) => Err(management_internal_error(
            request_id,
            "Database query failed",
        )),
    }
}

pub(in crate::web::management) async fn load_managed_user_identity_for_update(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    user_id: Uuid,
    request_id: &str,
) -> Result<ManagedUserIdentity, Response> {
    match load_user_identity_for_update(tx, team_id, environment_id, user_id).await {
        Ok(Some((subject, email, status))) if status != "DELETED" => Ok(ManagedUserIdentity {
            subject,
            email,
            status,
        }),
        Ok(Some(_) | None) => Err(user_not_found(request_id)),
        Err(_) => Err(management_internal_error(
            request_id,
            "Database query failed",
        )),
    }
}
