use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::federation::FederationError;

use super::super::config::DEFAULT_FEDERATION_CACHE_MAX_ENTRIES;
use super::super::traits::{RepositoryFuture, TrustChainCacheRepository};
use super::super::types::StoredTrustChain;
use super::error::storage_err;

/// PostgreSQL-backed trust chain cache repository.
///
/// Stores resolved trust chains as JSONB arrays of entity statement JWTs.
/// Expired entries are excluded from reads and can be pruned via `cleanup_expired`.
pub struct PgTrustChainCacheRepository {
    pool: PgPool,
    max_entries: usize,
}

impl PgTrustChainCacheRepository {
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

    fn row_to_stored(row: &sqlx::postgres::PgRow) -> Result<StoredTrustChain, FederationError> {
        Ok(StoredTrustChain {
            id: row.try_get("id").map_err(|err| storage_err(&err))?,
            environment_id: row
                .try_get("environment_id")
                .map_err(|err| storage_err(&err))?,
            leaf_entity_id: row
                .try_get("leaf_entity_id")
                .map_err(|err| storage_err(&err))?,
            anchor_entity_id: row
                .try_get("anchor_entity_id")
                .map_err(|err| storage_err(&err))?,
            chain_jwts: row.try_get("chain_jwts").map_err(|err| storage_err(&err))?,
            resolved_at: row
                .try_get::<i64, _>("resolved_epoch")
                .map_err(|err| storage_err(&err))?,
            expires_at: row
                .try_get::<i64, _>("expires_epoch")
                .map_err(|err| storage_err(&err))?,
        })
    }

    fn max_entries_i64(&self) -> Result<i64, FederationError> {
        self.max_entries.try_into().map_err(|_| {
            FederationError::Validation(
                "federation trust-chain cache limit is too large".to_string(),
            )
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
DELETE FROM aegaeon.federation_trust_chains cache
USING (
  SELECT id
  FROM (
    SELECT
      id,
      row_number() OVER (ORDER BY resolved_at DESC, id DESC) AS retention_rank
    FROM aegaeon.federation_trust_chains
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

impl TrustChainCacheRepository for PgTrustChainCacheRepository {
    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        leaf_entity_id: &'a str,
        anchor_entity_id: &'a str,
        now_epoch_secs: i64,
    ) -> RepositoryFuture<'a, Option<StoredTrustChain>> {
        Box::pin(async move {
            let row = sqlx::query(
                r"
SELECT
  id, environment_id, leaf_entity_id, anchor_entity_id, chain_jwts,
  EXTRACT(EPOCH FROM resolved_at)::bigint AS resolved_epoch,
  EXTRACT(EPOCH FROM expires_at)::bigint AS expires_epoch
FROM aegaeon.federation_trust_chains
WHERE environment_id = $1
  AND leaf_entity_id = $2
  AND anchor_entity_id = $3
  AND expires_at > to_timestamp($4::bigint)
                ",
            )
            .bind(environment_id)
            .bind(leaf_entity_id)
            .bind(anchor_entity_id)
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
        leaf_entity_id: &'a str,
        anchor_entity_id: &'a str,
        chain_jwts: &'a Value,
        expires_at_epoch_secs: i64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let max_entries = self.max_entries_i64()?;
            let mut tx = self.pool.begin().await.map_err(|err| storage_err(&err))?;
            Self::lock_environment_for_cache_write(&mut tx, environment_id).await?;
            sqlx::query(
                r"
INSERT INTO aegaeon.federation_trust_chains
  (environment_id, leaf_entity_id, anchor_entity_id, chain_jwts, expires_at)
VALUES ($1, $2, $3, $4, to_timestamp($5::bigint))
ON CONFLICT (environment_id, leaf_entity_id, anchor_entity_id) DO UPDATE SET
  chain_jwts = EXCLUDED.chain_jwts,
  resolved_at = now(),
  expires_at = EXCLUDED.expires_at
                ",
            )
            .bind(environment_id)
            .bind(leaf_entity_id)
            .bind(anchor_entity_id)
            .bind(chain_jwts)
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
                "DELETE FROM aegaeon.federation_trust_chains \
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
