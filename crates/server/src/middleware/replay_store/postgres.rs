//! Current, expiring replay decisions in the selected application database.
use super::{OwnedReplayEntry, ReplayEntry, ReplayFuture, ReplayStore, ReplayStoreError};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

pub(crate) struct PostgresReplayStore {
    pool: PgPool,
    namespace: String,
}

fn unavailable() -> ReplayStoreError {
    ReplayStoreError::BackendUnavailable("replay database unavailable".into())
}

impl PostgresReplayStore {
    pub(crate) fn new(pool: PgPool, namespace: String) -> Self {
        Self { pool, namespace }
    }

    async fn insert(&self, entry: OwnedReplayEntry) -> Result<(), ReplayStoreError> {
        // Round upward: a sub-millisecond remainder cannot shorten retention.
        let ttl_ms = entry.ttl.as_nanos().div_ceil(1_000_000).max(1);
        let ttl_ms = i64::try_from(ttl_ms).map_err(|_| ReplayStoreError::RetentionOverflow)?;
        let key = entry.borrowed().encoded_digest();
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        crate::organizations::request_work::async_store::admit_current_commit()
            .map_err(|_| unavailable())?;
        // One atomic statement. An unknown outcome is never retried or deleted.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            sqlx::query_scalar::<_, bool>("SELECT aegaeon.record_runtime_replay($1,$2,$3)")
                .bind(&self.namespace)
                .bind(key)
                .bind(ttl_ms)
                .fetch_one(connection.as_mut()?)
                .await
        })
        .await;
        connection.release().await;
        if result
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?
        {
            Ok(())
        } else {
            Err(ReplayStoreError::Replay)
        }
    }

    async fn cleanup(&self) -> Result<(), ReplayStoreError> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::Replay,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
        .map_err(|_| unavailable())
    }
}

impl ReplayStore for PostgresReplayStore {
    fn check_and_store(&self, _: ReplayEntry<'_>) -> Result<(), ReplayStoreError> {
        Err(ReplayStoreError::BackendUnavailable(
            "asynchronous replay admission required".into(),
        ))
    }

    fn check_and_store_async(self: Arc<Self>, entry: OwnedReplayEntry) -> ReplayFuture {
        Box::pin(async move { self.insert(entry).await })
    }

    fn cleanup_async(self: Arc<Self>) -> ReplayFuture {
        Box::pin(async move { self.cleanup().await })
    }
}

#[cfg(test)]
mod tests;
