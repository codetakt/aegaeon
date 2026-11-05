use super::{DpopEndpointRole, DpopError, DpopNonceStore, Duration};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use sqlx::PgPool;

pub(super) struct PostgresDpopNonceStore {
    pool: PgPool,
    namespace: String,
}

fn unavailable() -> DpopError {
    DpopError::BackendUnavailable("DPoP nonce database unavailable".into())
}

impl PostgresDpopNonceStore {
    pub(super) fn new(pool: PgPool, namespace: String) -> Self {
        Self { pool, namespace }
    }

    pub(super) async fn issue(
        &self,
        role: DpopEndpointRole,
        ttl: Duration,
    ) -> Result<String, DpopError> {
        let ttl_ms =
            i64::try_from(ttl.as_nanos().div_ceil(1_000_000)).map_err(|_| unavailable())?;
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_scalar("SELECT aegaeon.issue_runtime_dpop_nonce($1,$2,$3,$4)")
                .bind(&self.namespace)
                .bind(role.nonce_scope())
                .bind(DpopNonceStore::generate_nonce())
                .bind(ttl_ms)
                .fetch_one(connection.as_mut().map_err(|_| unavailable())?)
                .await
                .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn validate(
        &self,
        role: DpopEndpointRole,
        nonce: &str,
    ) -> Result<bool, DpopError> {
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM aegaeon.runtime_dpop_nonces WHERE namespace=$1 AND role=$2 AND ((current_value=$3 AND expires_at>statement_timestamp()) OR (previous_value=$3 AND previous_until>statement_timestamp())))")
                .bind(&self.namespace).bind(role.nonce_scope()).bind(nonce)
                .fetch_one(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn cleanup(&self) -> Result<(), DpopError> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::Nonce,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
        .map_err(|_| unavailable())
    }
}

#[cfg(test)]
mod tests;
