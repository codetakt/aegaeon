use axum::{http::StatusCode, response::Response};
use sqlx::{Executor, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::super::{
    error_response, is_unique_violation, management_internal_error, ManagementEnvironmentScope,
};

pub(in crate::web::management) async fn account_link_exists_by_upstream_subject<'e, E>(
    executor: E,
    environment_id: Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    request_id: &str,
) -> Result<bool, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar::<_, Uuid>(
        r"
SELECT id
FROM aegaeon.account_links
WHERE environment_id = $1
  AND upstream_issuer = $2
  AND upstream_sub_hash = $3
        ",
    )
    .bind(environment_id)
    .bind(upstream_issuer)
    .bind(upstream_sub_hash)
    .fetch_optional(executor)
    .await
    .map(|value| value.is_some())
    .map_err(|_| management_internal_error(request_id, "Database query failed"))
}

pub(in crate::web::management) async fn insert_account_link_id(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    connection_id: Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    end_user_id: Uuid,
    request_id: &str,
) -> Result<Uuid, Response> {
    sqlx::query_scalar::<_, Uuid>(
        r"
INSERT INTO aegaeon.account_links (
  environment_id,
  connection_id,
  upstream_issuer,
  upstream_sub_hash,
  end_user_id
)
VALUES ($1, $2, $3, $4, $5)
RETURNING id
        ",
    )
    .bind(scope.environment)
    .bind(connection_id)
    .bind(upstream_issuer)
    .bind(upstream_sub_hash)
    .bind(end_user_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            return error_response(
                StatusCode::CONFLICT,
                "conflict",
                "Account link already exists for this upstream account",
                None,
                Some(request_id),
            );
        }
        management_internal_error(request_id, "Failed to create account link")
    })
}

pub(in crate::web::management) async fn delete_account_link_row(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    account_link_id: Uuid,
    request_id: &str,
) -> Result<bool, Response> {
    sqlx::query(
        r"
DELETE FROM aegaeon.account_links
WHERE id = $1
  AND environment_id = $2
        ",
    )
    .bind(account_link_id)
    .bind(scope.environment)
    .execute(&mut **tx)
    .await
    .map(|result| result.rows_affected() > 0)
    .map_err(|_| management_internal_error(request_id, "Failed to delete account link"))
}
