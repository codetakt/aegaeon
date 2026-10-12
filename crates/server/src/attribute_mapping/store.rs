use aegaeon_attribute_mapping::{validate_attribute_value, MappingError, Provenance, SourceKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Executor, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttributeSourceRecord {
    pub namespace: String,
    pub revision: i64,
    pub provenance: Provenance,
    pub values: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum AttributeStoreError {
    #[error("attribute owner not found")]
    OwnerNotFound,
    #[error("attribute source revision changed")]
    RevisionMismatch { current: i64 },
    #[error("invalid attribute source input")]
    InvalidInput,
    #[error("invalid attribute source data")]
    InvalidData,
    #[error(transparent)]
    Mapping(#[from] MappingError),
    #[error("attribute source database operation failed")]
    Database(#[from] sqlx::Error),
}

fn validate_values(values: &Value) -> Result<(), AttributeStoreError> {
    validate_attribute_value(values)?;
    let Some(object) = values.as_object() else {
        return Err(AttributeStoreError::InvalidInput);
    };
    if object.keys().any(|name| {
        name.is_empty()
            || name.trim() != name
            || name.len() > 512
            || name.chars().any(char::is_control)
    }) {
        return Err(AttributeStoreError::InvalidInput);
    }
    Ok(())
}

fn from_row(row: &sqlx::postgres::PgRow) -> Result<AttributeSourceRecord, AttributeStoreError> {
    let kind: String = row.try_get("source_kind")?;
    let kind = match kind.as_str() {
        "LOCAL" => SourceKind::Local,
        "EXTERNAL" => SourceKind::External,
        _ => return Err(AttributeStoreError::InvalidData),
    };
    let values: Value = row.try_get("attribute_values")?;
    validate_values(&values).map_err(|_| AttributeStoreError::InvalidData)?;
    Ok(AttributeSourceRecord {
        namespace: row.try_get("source_namespace")?,
        revision: row.try_get("revision")?,
        provenance: Provenance {
            kind,
            authority: row.try_get("source_authority")?,
            source_revision: row.try_get("source_revision")?,
            observed_at: row.try_get("observed_at")?,
            expires_at: row.try_get("expires_at")?,
        },
        values,
    })
}

/// Load source namespaces belonging to one immutable environment/user pair.
/// The caller separately authorizes management reads or protocol disclosure.
///
/// # Errors
/// Returns an error on invalid stored data or a database failure.
pub async fn load_attribute_sources<'e>(
    executor: impl Executor<'e, Database = Postgres>,
    environment: Uuid,
    user: Uuid,
) -> Result<Vec<AttributeSourceRecord>, AttributeStoreError> {
    let rows = sqlx::query(
        r"
SELECT a.source_namespace, a.revision, a.source_kind, a.source_authority,
       a.source_revision, a.observed_at, a.expires_at,
       CASE WHEN sum(octet_length(a.attribute_values::text)) OVER () <= 1048576
            THEN a.attribute_values ELSE 'null'::jsonb END AS attribute_values
FROM aegaeon.user_attribute_sources a
JOIN aegaeon.end_users u ON u.id = a.end_user_id AND u.environment_id = a.environment_id
WHERE a.environment_id = $1 AND a.end_user_id = $2 AND u.status <> 'DELETED'
ORDER BY a.source_namespace
LIMIT 1025",
    )
    .bind(environment)
    .bind(user)
    .fetch_all(executor)
    .await?;
    if rows.len() > 1024 {
        return Err(AttributeStoreError::InvalidData);
    }
    rows.iter().map(from_row).collect()
}

/// Replace the local namespace under the caller's authorized transaction.
/// Base revision zero creates an absent namespace. Replacing with an empty
/// object deletes its values while retaining the monotonically increasing
/// revision. This operation cannot write an external connection's namespace.
///
/// # Errors
/// Returns an error on invalid input, missing owner, stale revision or DB failure.
pub async fn replace_local_attributes(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    user: Uuid,
    base_revision: i64,
    values: &Value,
    actor: Uuid,
) -> Result<AttributeSourceRecord, AttributeStoreError> {
    validate_values(values)?;
    if base_revision < 0 {
        return Err(AttributeStoreError::InvalidInput);
    }
    // Serializes both initial insertion and replacement with user lifecycle work.
    let found = sqlx::query(
        r"
SELECT id FROM aegaeon.end_users
WHERE environment_id = $1 AND id = $2 AND status <> 'DELETED' FOR UPDATE",
    )
    .bind(environment)
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    if found.is_none() {
        return Err(AttributeStoreError::OwnerNotFound);
    }
    let current = sqlx::query(
        r"
SELECT revision FROM aegaeon.user_attribute_sources
WHERE environment_id = $1 AND end_user_id = $2 AND source_namespace = 'local'",
    )
    .bind(environment)
    .bind(user)
    .fetch_optional(&mut **tx)
    .await?;
    let current: i64 = current
        .map(|row| row.try_get("revision"))
        .transpose()?
        .unwrap_or(0);
    if current != base_revision {
        return Err(AttributeStoreError::RevisionMismatch { current });
    }
    let next = current
        .checked_add(1)
        .ok_or(AttributeStoreError::InvalidData)?;
    let row = sqlx::query(r"
INSERT INTO aegaeon.user_attribute_sources
  (environment_id, end_user_id, source_namespace, source_kind, source_authority,
   source_revision, observed_at, attribute_values, revision)
VALUES ($1, $2, 'local', 'LOCAL', $3, $4, floor(extract(epoch FROM clock_timestamp()))::bigint, $5, $6)
ON CONFLICT (environment_id, end_user_id, source_namespace) DO UPDATE
SET source_authority = EXCLUDED.source_authority, source_revision = EXCLUDED.source_revision,
    observed_at = EXCLUDED.observed_at, attribute_values = EXCLUDED.attribute_values,
    revision = EXCLUDED.revision, updated_at = now()
RETURNING *")
        .bind(environment).bind(user).bind(format!("management:{actor}"))
        .bind(next.to_string()).bind(values).bind(next).fetch_one(&mut **tx).await?;
    from_row(&row)
}
