use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::federation::FederationError;

use super::super::config::DEFAULT_FEDERATION_CACHE_MAX_ENTRIES;
use super::super::traits::{EntityCacheRepository, RepositoryFuture};
use super::super::types::StoredEntityCache;
use super::error::storage_err;

/// PostgreSQL-backed entity cache repository.
///
/// Stores fetched Entity Configuration JWS with TTL expiry. Expired entries
/// are excluded from reads and can be pruned via `cleanup_expired`.
pub struct PgEntityCacheRepository {
    pool: PgPool,
    max_entries: usize,
}

impl PgEntityCacheRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self::with_max_entries(pool, DEFAULT_FEDERATION_CACHE_MAX_ENTRIES)
    }

    #[must_use]
    pub fn with_max_entries(pool: PgPool, max_entries: usize) -> Self {
        Self {
            pool,
            max_entries: max_entries.max(1),
        }
    }

    fn row_to_stored(row: &sqlx::postgres::PgRow) -> Result<StoredEntityCache, FederationError> {
        Ok(StoredEntityCache {
            id: row.try_get("id").map_err(|err| storage_err(&err))?,
            environment_id: row
                .try_get("environment_id")
                .map_err(|err| storage_err(&err))?,
            entity_id: row.try_get("entity_id").map_err(|err| storage_err(&err))?,
            entity_configuration_jws: row
                .try_get("entity_configuration_jws")
                .map_err(|err| storage_err(&err))?,
            parsed_statement: row
                .try_get("parsed_statement")
                .map_err(|err| storage_err(&err))?,
            fetched_at: row
                .try_get::<i64, _>("fetched_epoch")
                .map_err(|err| storage_err(&err))?,
            expires_at: row
                .try_get::<i64, _>("expires_epoch")
                .map_err(|err| storage_err(&err))?,
        })
    }

    fn max_entries_i64(&self) -> Result<i64, FederationError> {
        self.max_entries.try_into().map_err(|_| {
            FederationError::Validation("federation entity cache limit is too large".to_string())
        })
    }

    async fn lock_environment_for_cache_write(
        tx: &mut Transaction<'_, Postgres>,
        environment_id: Uuid,
    ) -> Result<(), FederationError> {
        sqlx::query("SELECT e.id FROM aegaeon.environments e WHERE e.id = $1 FOR UPDATE OF e")
            .bind(environment_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(|err| storage_err(&err))?;
        Ok(())
    }

    async fn prune_to_max_entries_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        environment_id: Uuid,
        max_entries: i64,
    ) -> Result<(), FederationError> {
        sqlx::query(
            r"
DELETE FROM aegaeon.federation_entity_cache cache
USING (
  SELECT id
  FROM (
    SELECT
      id,
      row_number() OVER (ORDER BY fetched_at DESC, id DESC) AS retention_rank
    FROM aegaeon.federation_entity_cache
    WHERE environment_id = $1
  ) ranked
  WHERE retention_rank > $2
) stale
WHERE cache.id = stale.id
            ",
        )
        .bind(environment_id)
        .bind(max_entries)
        .execute(&mut **tx)
        .await
        .map_err(|err| storage_err(&err))?;
        Ok(())
    }
}

impl EntityCacheRepository for PgEntityCacheRepository {
    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
        now_epoch_secs: i64,
    ) -> RepositoryFuture<'a, Option<StoredEntityCache>> {
        Box::pin(async move {
            let row = sqlx::query(
                r"
SELECT
  id, environment_id, entity_id, entity_configuration_jws, parsed_statement,
  EXTRACT(EPOCH FROM fetched_at)::bigint AS fetched_epoch,
  EXTRACT(EPOCH FROM expires_at)::bigint AS expires_epoch
FROM aegaeon.federation_entity_cache
WHERE environment_id = $1
  AND entity_id = $2
  AND expires_at > to_timestamp($3::bigint)
                ",
            )
            .bind(environment_id)
            .bind(entity_id)
            .bind(now_epoch_secs)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| storage_err(&err))?;

            row.as_ref().map(Self::row_to_stored).transpose()
        })
    }

    fn upsert<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
        jws: &'a str,
        parsed: &'a Value,
        expires_at_epoch_secs: i64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let max_entries = self.max_entries_i64()?;
            let mut tx = self.pool.begin().await.map_err(|err| storage_err(&err))?;
            Self::lock_environment_for_cache_write(&mut tx, environment_id).await?;
            sqlx::query(
                r"
INSERT INTO aegaeon.federation_entity_cache
  (environment_id, entity_id, entity_configuration_jws, parsed_statement, expires_at)
VALUES ($1, $2, $3, $4, to_timestamp($5::bigint))
ON CONFLICT (environment_id, entity_id) DO UPDATE SET
  entity_configuration_jws = EXCLUDED.entity_configuration_jws,
  parsed_statement = EXCLUDED.parsed_statement,
  fetched_at = now(),
  expires_at = EXCLUDED.expires_at
                ",
            )
            .bind(environment_id)
            .bind(entity_id)
            .bind(jws)
            .bind(parsed)
            .bind(expires_at_epoch_secs)
            .execute(&mut *tx)
            .await
            .map_err(|err| storage_err(&err))?;
            Self::prune_to_max_entries_in_tx(&mut tx, environment_id, max_entries).await?;
            tx.commit().await.map_err(|err| storage_err(&err))?;

            Ok(())
        })
    }

    fn cleanup_expired(&self, now_epoch_secs: i64) -> RepositoryFuture<'_, u64> {
        Box::pin(async move {
            let result = sqlx::query(
                "DELETE FROM aegaeon.federation_entity_cache \
                 WHERE expires_at <= to_timestamp($1::bigint)",
            )
            .bind(now_epoch_secs)
            .execute(&self.pool)
            .await
            .map_err(|err| storage_err(&err))?;

            Ok(result.rows_affected())
        })
    }
}
