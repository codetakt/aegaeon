use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::Connection;

use super::super::{management_internal_error, parse_optional_stored_uuid};
use super::mapper::{connection_from_row_result, parse_connection_configuration_version_id};

#[derive(Clone, Debug)]
pub(in crate::web::management) struct RetirableConnection {
    pub(in crate::web::management) connection: Connection,
    pub(in crate::web::management) configuration_version_id: Uuid,
    pub(in crate::web::management) oauth_profile_id: Option<Uuid>,
}

pub(in crate::web::management) async fn load_retirable_connection(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    connection_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<Option<RetirableConnection>, Response> {
    let row = sqlx::query(
        r#"
SELECT
  id,
  environment_id,
  configuration_version_id,
  oauth_profile_id,
  connection_identifier,
  name,
  connection_type::text AS connection_type,
  issuer_url,
  client_id,
  client_auth_method,
  status::text AS status,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.connections
WHERE id = $1
  AND environment_id = $2
  AND configuration_version_id = $3
  AND status <> 'DELETED'
        "#,
    )
    .bind(connection_id)
    .bind(environment_id)
    .bind(configuration_version_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to load connection"))?;

    let Some(row) = row else {
        return Ok(None);
    };
    let connection = connection_from_row_result(&row, request_id)?;

    Ok(Some(RetirableConnection {
        configuration_version_id: parse_connection_configuration_version_id(
            &connection,
            request_id,
        )?,
        oauth_profile_id: parse_optional_stored_uuid(
            connection.oauth_profile_id.as_deref(),
            "connection oauthProfileId",
            request_id,
        )?,
        connection,
    }))
}

pub(in crate::web::management) async fn retire_connection(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    connection_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<u64, Response> {
    sqlx::query(
        r"
UPDATE aegaeon.connections
SET status = 'DELETED', deleted_at = now(), updated_at = now()
WHERE id = $1
  AND environment_id = $2
  AND configuration_version_id = $3
  AND status <> 'DELETED'
        ",
    )
    .bind(connection_id)
    .bind(environment_id)
    .bind(configuration_version_id)
    .execute(&mut **tx)
    .await
    .map(|result| result.rows_affected())
    .map_err(|_| management_internal_error(request_id, "Failed to delete connection"))
}
