use super::{CsrfTokenStoreError, Duration};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use sqlx::PgPool;

pub(in crate::device_authz) struct PostgresCsrfTokenStore {
    pool: PgPool,
    namespace: String,
}

fn unavailable() -> CsrfTokenStoreError {
    CsrfTokenStoreError::BackendUnavailable("CSRF token database unavailable".into())
}

impl PostgresCsrfTokenStore {
    pub(super) fn new(pool: PgPool, namespace: String) -> Self {
        Self { pool, namespace }
    }

    pub(super) async fn insert(
        &self,
        token: &str,
        ttl: Duration,
    ) -> Result<bool, CsrfTokenStoreError> {
        let ttl_ms = i64::try_from(ttl.as_nanos().div_ceil(1_000_000))
            .map_err(|_| CsrfTokenStoreError::RetentionOverflow)?;
        if ttl_ms < 1 {
            return Err(CsrfTokenStoreError::RetentionOverflow);
        }
        let digest = aegaeon_crypto::hash::sha256_digest(token.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query("INSERT INTO aegaeon.runtime_csrf_tokens(namespace,token_digest,expires_at) VALUES($1,$2,clock_timestamp()+$3*interval '1 millisecond') ON CONFLICT DO NOTHING")
                .bind(&self.namespace).bind(digest.as_slice()).bind(ttl_ms)
                .execute(connection.as_mut().map_err(|_| unavailable())?).await
                .map(|result| result.rows_affected()==1).map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn consume(&self, token: &str) -> Result<bool, CsrfTokenStoreError> {
        let digest = aegaeon_crypto::hash::sha256_digest(token.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query_scalar::<_, bool>("DELETE FROM aegaeon.runtime_csrf_tokens WHERE namespace=$1 AND token_digest=$2 RETURNING expires_at>clock_timestamp()")
                .bind(&self.namespace).bind(digest.as_slice())
                .fetch_optional(connection.as_mut().map_err(|_| unavailable())?).await
                .map(|value| value.unwrap_or(false)).map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn cleanup(&self) -> Result<(), CsrfTokenStoreError> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::Csrf,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
        .map_err(|_| unavailable())
    }
}

#[cfg(test)]
mod tests;
