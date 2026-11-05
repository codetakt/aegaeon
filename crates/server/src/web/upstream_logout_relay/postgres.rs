use super::{Duration, UpstreamLogoutRelayState};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub(super) struct PostgresLogoutRelayStore {
    pool: PgPool,
    namespace: String,
}

fn unavailable() -> String {
    "upstream logout relay database unavailable".into()
}

impl PostgresLogoutRelayStore {
    pub(super) fn new(pool: PgPool, namespace: String) -> Self {
        Self { pool, namespace }
    }

    pub(super) async fn insert(
        &self,
        token: &str,
        value: &UpstreamLogoutRelayState,
        ttl: Duration,
    ) -> Result<(), String> {
        let ttl_ms =
            i64::try_from(ttl.as_nanos().div_ceil(1_000_000)).map_err(|_| unavailable())?;
        if ttl_ms < 1 {
            return Err(unavailable());
        }
        let digest = aegaeon_crypto::hash::sha256_digest(token.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            let count=sqlx::query("INSERT INTO aegaeon.runtime_logout_relays(namespace,token_digest,incident_id,downstream_redirect_uri,downstream_state,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+$6*interval '1 millisecond') ON CONFLICT DO NOTHING")
                .bind(&self.namespace).bind(digest.as_slice()).bind(value.incident_id).bind(&value.downstream_redirect_uri).bind(&value.downstream_state).bind(ttl_ms)
                .execute(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?.rows_affected();
            if count==1 { Ok(()) } else { Err("upstream logout relay state already exists".into()) }
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn take(
        &self,
        token: &str,
    ) -> Result<Option<UpstreamLogoutRelayState>, String> {
        let digest = aegaeon_crypto::hash::sha256_digest(token.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            let row=sqlx::query("DELETE FROM aegaeon.runtime_logout_relays WHERE namespace=$1 AND token_digest=$2 RETURNING incident_id,downstream_redirect_uri,downstream_state,expires_at>clock_timestamp() AS live")
                .bind(&self.namespace).bind(digest.as_slice()).fetch_optional(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())?;
            let Some(row)=row else { return Ok(None); };
            if !row.try_get::<bool,_>("live").map_err(|_| unavailable())? { return Ok(None); }
            Ok(Some(UpstreamLogoutRelayState {
                incident_id:row.try_get("incident_id").map_err(|_| unavailable())?,
                downstream_redirect_uri:row.try_get("downstream_redirect_uri").map_err(|_| unavailable())?,
                downstream_state:row.try_get("downstream_state").map_err(|_| unavailable())?,
            }))
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        result
    }

    pub(super) async fn cleanup(&self) -> Result<(), String> {
        crate::runtime_security_cleanup::cleanup(
            &self.pool,
            &self.namespace,
            crate::runtime_security_cleanup::Kind::LogoutRelay,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests;
