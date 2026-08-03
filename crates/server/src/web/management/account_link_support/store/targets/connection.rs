use axum::{http::StatusCode, response::Response};
use sqlx::{Executor, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::super::{
    error_response, management_internal_error, ManagementEnvironmentScope,
};
use super::super::super::mapper::{
    account_link_connection_from_row_result, AccountLinkConnectionRecord,
};

pub(in crate::web::management) const LOAD_ACCOUNT_LINK_CONNECTION_SQL: &str = r"
SELECT
  c.id,
  c.connection_identifier,
  c.name,
  c.issuer_url
FROM aegaeon.connections c
JOIN aegaeon.environments e ON e.id = c.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE c.id = $1
  AND c.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status = 'ACTIVE'
  AND e.active_configuration_version_id = c.configuration_version_id
  AND c.status = 'ACTIVE'
        ";

const LOAD_ACCOUNT_LINK_CONNECTION_FOR_UPDATE_SQL: &str = r"
SELECT
  c.id,
  c.connection_identifier,
  c.name,
  c.issuer_url
FROM aegaeon.connections c
JOIN aegaeon.environments e ON e.id = c.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE c.id = $1
  AND c.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status = 'ACTIVE'
  AND e.active_configuration_version_id = c.configuration_version_id
  AND c.status = 'ACTIVE'
FOR UPDATE OF c
        ";

pub(in crate::web::management) async fn load_account_link_connection<'e, E>(
    executor: E,
    scope: ManagementEnvironmentScope,
    connection_id: Uuid,
    request_id: &str,
) -> Result<AccountLinkConnectionRecord, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    load_account_link_connection_with_sql(
        executor,
        LOAD_ACCOUNT_LINK_CONNECTION_SQL,
        scope,
        connection_id,
        request_id,
    )
    .await
}

pub(in crate::web::management) async fn load_account_link_connection_for_update(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    connection_id: Uuid,
    request_id: &str,
) -> Result<AccountLinkConnectionRecord, Response> {
    load_account_link_connection_with_sql(
        &mut **tx,
        LOAD_ACCOUNT_LINK_CONNECTION_FOR_UPDATE_SQL,
        scope,
        connection_id,
        request_id,
    )
    .await
}

async fn load_account_link_connection_with_sql<'e, E>(
    executor: E,
    sql: &str,
    scope: ManagementEnvironmentScope,
    connection_id: Uuid,
    request_id: &str,
) -> Result<AccountLinkConnectionRecord, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(sql)
        .bind(connection_id)
        .bind(scope.environment)
        .bind(scope.team)
        .fetch_optional(executor)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Connection not found",
                None,
                Some(request_id),
            )
        })?;

    account_link_connection_from_row_result(&row, request_id)
}
