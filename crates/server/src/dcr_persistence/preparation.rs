use sqlx::{Postgres, Row, Transaction};

use super::{DcrDatabaseError, DcrStoredClient};

// Only presence belongs to this decision: adding an overlapping eligible secret
// must not invalidate Preserve, and issuance configuration is provenance.
pub(super) const ELIGIBLE_SECRET_SQL: &str = r"
EXISTS (
  SELECT 1 FROM aegaeon.client_secrets cs
  WHERE cs.environment_id = c.environment_id AND cs.client_id = c.id
    AND cs.status = 'ACTIVE' AND cs.secret_hash_algorithm = 'argon2id'
    AND cs.expires_at > statement_timestamp()
)";

// Keep the same complete-row inventory for preload and protected reread. Only
// bookkeeping timestamps are excluded. Semantic timestamps use exact epoch text
// independent of connection TimeZone. Preserve PostgreSQL's JSONB text rather
// than decoding numbers through floating point in serde_json::Value.
pub(super) fn snapshot_sql() -> String {
    format!(
        r"jsonb_build_array(
          (to_jsonb(c) - 'created_at' - 'updated_at' - 'deleted_at') ||
            jsonb_build_object('deleted_at', EXTRACT(EPOCH FROM c.deleted_at)::text),
          (to_jsonb(dcr) - 'created_at' - 'updated_at' - 'client_id_issued_at') ||
            jsonb_build_object('client_id_issued_at', EXTRACT(EPOCH FROM dcr.client_id_issued_at)::text),
          {ELIGIBLE_SECRET_SQL}
        )::text"
    )
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PreparationSnapshot(String);

impl PreparationSnapshot {
    pub(super) fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        row.try_get("preparation_snapshot").map(Self)
    }
}

pub(super) async fn check_current_preparation(
    tx: &mut Transaction<'_, Postgres>,
    stored: &DcrStoredClient,
) -> Result<(), DcrDatabaseError> {
    // This must remain a separate statement AFTER all lock waits. Transaction
    // now() or a statement started before waiting would retain an expired secret.
    let query = format!(
        "SELECT {} AS preparation_snapshot
         FROM aegaeon.clients c JOIN aegaeon.dynamic_client_registrations dcr
           ON dcr.environment_id = c.environment_id AND dcr.client_id = c.id
         WHERE c.environment_id = $1 AND c.id = $2",
        snapshot_sql()
    );
    let row = sqlx::query(&query)
        .bind(stored.environment_id)
        .bind(stored.database_client_id)
        .fetch_optional(&mut **tx)
        .await?;
    let current = row
        .as_ref()
        .map(PreparationSnapshot::from_row)
        .transpose()?;
    if current.as_ref() == Some(&stored.preparation_snapshot) {
        Ok(())
    } else {
        Err(DcrDatabaseError::ConcurrentModification)
    }
}
