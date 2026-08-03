use axum::{http::StatusCode, response::Response};
use sqlx::{postgres::PgRow, Postgres, Transaction};

use crate::management::types::ApiKeyCapability;
use crate::web::management::error_response;

use super::model::ApiKeyInsertInput;

pub(in crate::web::management::api_keys) async fn insert_api_key_row(
    tx: &mut Transaction<'_, Postgres>,
    input: &ApiKeyInsertInput<'_>,
    request_id: &str,
) -> Result<PgRow, Response> {
    insert_service_administrator(tx, input, request_id).await?;
    insert_service_team_membership(tx, input, request_id).await?;

    sqlx::query(
        r#"
INSERT INTO aegaeon.api_keys (
  id,
  team_id,
  service_administrator_id,
  name,
  key_prefix,
  key_hash,
  created_by_administrator_id,
  expires_at
)
VALUES (
  $8,
  $1,
  $7,
  $2,
  $3,
  $4,
  $6,
  CASE
    WHEN $5::integer IS NULL THEN NULL
    ELSE now() + make_interval(days => $5)
  END
)
        "#,
    )
    .bind(input.team_id)
    .bind(input.name)
    .bind(input.key_prefix)
    .bind(input.key_hash)
    .bind(input.expires_in_days)
    .bind(input.created_by_administrator_id)
    .bind(input.service_administrator_id)
    .bind(input.api_key_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to create API key",
            None,
            Some(request_id),
        )
    })?;
    insert_api_key_capabilities(tx, input, request_id).await?;
    load_api_key_row(tx, input.api_key_id, request_id).await
}

async fn insert_service_administrator(
    tx: &mut Transaction<'_, Postgres>,
    input: &ApiKeyInsertInput<'_>,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.administrators (
  id, email, password_hash, kind, status
)
VALUES ($1, $2, 'service-principal-disabled', 'SERVICE', 'ACTIVE')
        ",
    )
    .bind(input.service_administrator_id)
    .bind(service_administrator_email(input.api_key_id))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to create API key service principal",
            None,
            Some(request_id),
        )
    })
}

async fn insert_service_team_membership(
    tx: &mut Transaction<'_, Postgres>,
    input: &ApiKeyInsertInput<'_>,
    request_id: &str,
) -> Result<(), Response> {
    sqlx::query(
        r"
INSERT INTO aegaeon.team_memberships (
  team_id, administrator_id, role
)
VALUES ($1, $2, $3::aegaeon.team_role)
        ",
    )
    .bind(input.team_id)
    .bind(input.service_administrator_id)
    .bind(team_role_for_capabilities(input.capabilities))
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to bind API key service principal to team",
            None,
            Some(request_id),
        )
    })
}

async fn insert_api_key_capabilities(
    tx: &mut Transaction<'_, Postgres>,
    input: &ApiKeyInsertInput<'_>,
    request_id: &str,
) -> Result<(), Response> {
    let capabilities = input
        .capabilities
        .iter()
        .map(|capability| capability.as_db_value())
        .collect::<Vec<_>>();
    sqlx::query(
        r"
INSERT INTO aegaeon.api_key_capabilities (
  api_key_id, capability
)
SELECT $1, capability::aegaeon.api_key_capability
FROM unnest($2::text[]) AS capability
        ",
    )
    .bind(input.api_key_id)
    .bind(capabilities)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to bind API key capabilities",
            None,
            Some(request_id),
        )
    })
}

fn team_role_for_capabilities(_capabilities: &[ApiKeyCapability]) -> &'static str {
    "READONLY"
}

async fn load_api_key_row(
    tx: &mut Transaction<'_, Postgres>,
    api_key_id: uuid::Uuid,
    request_id: &str,
) -> Result<PgRow, Response> {
    sqlx::query(
        r#"
SELECT
  ak.id,
  ak.team_id,
  ak.name,
  ak.key_prefix,
  ARRAY(
    SELECT akc.capability::text
    FROM aegaeon.api_key_capabilities akc
    WHERE akc.api_key_id = ak.id
    ORDER BY akc.capability::text
  ) AS capabilities,
  ak.status::text AS status,
  to_char(ak.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
  to_char(ak.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
FROM aegaeon.api_keys ak
WHERE ak.id = $1
        "#,
    )
    .bind(api_key_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Failed to create API key",
            None,
            Some(request_id),
        )
    })
}

fn service_administrator_email(api_key_id: uuid::Uuid) -> String {
    format!("api-key-{api_key_id}@api-key.aegaeon.internal")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_service_principal_role_is_minimal_for_all_capabilities() {
        assert_eq!(
            team_role_for_capabilities(&[ApiKeyCapability::TeamAdministration]),
            "READONLY"
        );
        assert_eq!(
            team_role_for_capabilities(&[ApiKeyCapability::AuditRead]),
            "READONLY"
        );
        assert_eq!(
            team_role_for_capabilities(&[ApiKeyCapability::Read, ApiKeyCapability::AuditRead]),
            "READONLY"
        );
    }
}
