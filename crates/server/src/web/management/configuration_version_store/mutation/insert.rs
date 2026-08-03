use sqlx::{postgres::PgRow, Postgres, Transaction};
use uuid::Uuid;

use super::super::super::configuration_documents::PreparedConfigurationDocument;

pub(in crate::web::management) async fn insert_configuration_version_row(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    next_version_number: i64,
    base_configuration_version_id: Uuid,
    administrator_id: Uuid,
    comment: Option<&str>,
    prepared_document: &PreparedConfigurationDocument,
) -> Result<PgRow, sqlx::Error> {
    sqlx::query(
        r#"
INSERT INTO aegaeon.configuration_versions (
  environment_id,
  version_number,
  schema_version,
  configuration_hash,
  status,
  base_configuration_version_id,
  configuration_document,
  created_by_administrator_id,
  comment
)
VALUES ($1, $2, 1, $3, 'DRAFT', $4, $5::jsonb, $6, $7)
RETURNING
  id,
  environment_id,
  version_number,
  schema_version,
  configuration_hash,
  status::text AS status,
  comment,
  configuration_document,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
        "#,
    )
    .bind(environment_id)
    .bind(next_version_number)
    .bind(&prepared_document.hash)
    .bind(base_configuration_version_id)
    .bind(&prepared_document.document)
    .bind(administrator_id)
    .bind(comment)
    .fetch_one(&mut **tx)
    .await
}
