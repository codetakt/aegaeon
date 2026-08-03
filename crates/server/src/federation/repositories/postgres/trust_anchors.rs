use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::federation::FederationError;

use super::super::traits::{RepositoryFuture, TrustAnchorRepository};
use super::super::types::StoredTrustAnchor;
use super::error::storage_err;

/// PostgreSQL-backed trust anchor repository.
///
/// All operations are scoped by `environment_id` to enforce tenant isolation.
/// Uses parameterized queries (sqlx bind) to prevent SQL injection.
pub struct PgTrustAnchorRepository {
    pool: PgPool,
}

impl PgTrustAnchorRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn row_to_stored(row: &sqlx::postgres::PgRow) -> Result<StoredTrustAnchor, FederationError> {
        Ok(StoredTrustAnchor {
            id: row.try_get("id").map_err(|err| storage_err(&err))?,
            environment_id: row
                .try_get("environment_id")
                .map_err(|err| storage_err(&err))?,
            entity_id: row.try_get("entity_id").map_err(|err| storage_err(&err))?,
            jwks: row.try_get("jwks").map_err(|err| storage_err(&err))?,
            metadata_policy: row
                .try_get("metadata_policy")
                .map_err(|err| storage_err(&err))?,
            created_at: row
                .try_get::<i64, _>("created_epoch")
                .map_err(|err| storage_err(&err))?,
            updated_at: row
                .try_get::<i64, _>("updated_epoch")
                .map_err(|err| storage_err(&err))?,
        })
    }
}

impl TrustAnchorRepository for PgTrustAnchorRepository {
    fn list_for_environment(
        &self,
        environment_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<StoredTrustAnchor>> {
        Box::pin(async move {
            let rows = sqlx::query(
                r"
SELECT
  id, environment_id, entity_id, jwks, metadata_policy,
  EXTRACT(EPOCH FROM created_at)::bigint AS created_epoch,
  EXTRACT(EPOCH FROM updated_at)::bigint AS updated_epoch
FROM aegaeon.federation_trust_anchors
WHERE environment_id = $1
ORDER BY created_at
                ",
            )
            .bind(environment_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|err| storage_err(&err))?;

            rows.iter().map(Self::row_to_stored).collect()
        })
    }

    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
    ) -> RepositoryFuture<'a, Option<StoredTrustAnchor>> {
        Box::pin(async move {
            let row = sqlx::query(
                r"
SELECT
  id, environment_id, entity_id, jwks, metadata_policy,
  EXTRACT(EPOCH FROM created_at)::bigint AS created_epoch,
  EXTRACT(EPOCH FROM updated_at)::bigint AS updated_epoch
FROM aegaeon.federation_trust_anchors
WHERE environment_id = $1 AND entity_id = $2
                ",
            )
            .bind(environment_id)
            .bind(entity_id)
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
        jwks: &'a Value,
        metadata_policy: Option<&'a Value>,
    ) -> RepositoryFuture<'a, StoredTrustAnchor> {
        Box::pin(async move {
            let row = sqlx::query(
                r"
INSERT INTO aegaeon.federation_trust_anchors
  (environment_id, entity_id, jwks, metadata_policy)
VALUES ($1, $2, $3, $4)
ON CONFLICT (environment_id, entity_id) DO UPDATE SET
  jwks = EXCLUDED.jwks,
  metadata_policy = EXCLUDED.metadata_policy,
  updated_at = now()
RETURNING
  id, environment_id, entity_id, jwks, metadata_policy,
  EXTRACT(EPOCH FROM created_at)::bigint AS created_epoch,
  EXTRACT(EPOCH FROM updated_at)::bigint AS updated_epoch
                ",
            )
            .bind(environment_id)
            .bind(entity_id)
            .bind(jwks)
            .bind(metadata_policy)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| storage_err(&err))?;

            Self::row_to_stored(&row)
        })
    }

    fn delete<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            let result = sqlx::query(
                r"
DELETE FROM aegaeon.federation_trust_anchors
WHERE environment_id = $1 AND entity_id = $2
                ",
            )
            .bind(environment_id)
            .bind(entity_id)
            .execute(&self.pool)
            .await
            .map_err(|err| storage_err(&err))?;

            Ok(result.rows_affected() > 0)
        })
    }
}
