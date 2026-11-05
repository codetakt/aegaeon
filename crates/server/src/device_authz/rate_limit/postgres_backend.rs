//! Durable, atomic security budgets. Cache loss cannot replenish attempts.
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use sqlx::PgPool;
use std::time::Duration;

pub(super) struct PostgresVerificationRateLimiter {
    pool: PgPool,
    namespace: String,
}

impl PostgresVerificationRateLimiter {
    pub(super) fn new(pool: PgPool, namespace: String) -> Self {
        Self { pool, namespace }
    }

    pub(super) async fn check_all(
        &self,
        buckets: &[&str],
        max_attempts: u32,
        window: Duration,
    ) -> Result<bool, String> {
        if max_attempts == 0 || buckets.len() > 16 || buckets.iter().any(|b| b.len() > 4096) {
            return Err("invalid security budget input".into());
        }
        if buckets.is_empty() {
            return Ok(true);
        }
        let window_ms = i64::try_from(window.as_millis())
            .ok()
            .filter(|ms| (1..=86_400_000).contains(ms))
            .ok_or("invalid security budget window")?;
        let keys: Vec<Vec<u8>> = buckets
            .iter()
            .map(|bucket| aegaeon_crypto::hash::sha256_digest(bucket.as_bytes()).to_vec())
            .collect();
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| "security budget database unavailable")?;
        crate::organizations::request_work::async_store::admit_current_commit()
            .map_err(|_| "security budget admission unavailable")?;
        // No retry after an unknown response: a committed charge stays charged.
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            sqlx::query_scalar("SELECT aegaeon.consume_runtime_security_budget($1,$2,$3,$4)")
                .bind(&self.namespace)
                .bind(keys)
                .bind(i64::from(max_attempts))
                .bind(window_ms)
                .fetch_one(connection.as_mut()?)
                .await
        })
        .await;
        connection.release().await;
        result
            .map_err(|_| "security budget database deadline".to_string())?
            .map_err(|_| "security budget database unavailable".into())
    }

    pub(super) async fn cleanup(&self) -> Result<(), String> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::Budget,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests;
