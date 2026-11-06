use super::*;
use crate::runtime_security_cleanup::{BATCH_ROWS, PASS_BATCHES};

// No cascading deletion: each statement has its own bounded set of locked rows.
const DELETES: [&str;3] = [
    "DELETE FROM aegaeon.runtime_oidc_auth_bindings WHERE ctid IN (SELECT b.ctid FROM aegaeon.runtime_oidc_auth_bindings b JOIN aegaeon.runtime_oidc_sessions s ON (s.namespace,s.sid)=(b.namespace,b.sid) WHERE b.namespace=$1 AND s.expires_at<=statement_timestamp() ORDER BY s.expires_at,b.sid LIMIT $2 FOR UPDATE OF b SKIP LOCKED)",
    "DELETE FROM aegaeon.runtime_oidc_clients WHERE ctid IN (SELECT c.ctid FROM aegaeon.runtime_oidc_clients c JOIN aegaeon.runtime_oidc_sessions s ON (s.namespace,s.sid)=(c.namespace,c.sid) WHERE c.namespace=$1 AND s.expires_at<=statement_timestamp() ORDER BY s.expires_at,c.sid,c.client_id LIMIT $2 FOR UPDATE OF c SKIP LOCKED)",
    "DELETE FROM aegaeon.runtime_oidc_sessions WHERE ctid IN (SELECT s.ctid FROM aegaeon.runtime_oidc_sessions s WHERE s.namespace=$1 AND s.expires_at<=statement_timestamp() AND NOT EXISTS(SELECT 1 FROM aegaeon.runtime_oidc_auth_bindings b WHERE (b.namespace,b.sid)=(s.namespace,s.sid)) AND NOT EXISTS(SELECT 1 FROM aegaeon.runtime_oidc_clients c WHERE (c.namespace,c.sid)=(s.namespace,s.sid)) ORDER BY s.expires_at,s.sid LIMIT $2 FOR UPDATE OF s SKIP LOCKED)",
];

impl PostgresOidcSessionBackend {
    pub(in crate::oidc::session::imp) async fn cleanup(&self) -> Result<(), String> {
        let result = self.cleanup_inner().await;
        crate::runtime_security_cleanup::record_oidc_cleanup(
            result.0,
            result.1.as_ref().ok().copied(),
        );
        result.1.map(|_| ())
    }

    async fn cleanup_inner(&self) -> (u64, Result<bool, String>) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut connection = match AdmittedConnection::acquire(&self.database.pool).await {
            Ok(connection) => connection,
            Err(_) => return (0, Err(unavailable())),
        };
        let mut removed = 0_u64;
        let result=async {
            for _ in 0..PASS_BATCHES {
                let before=removed;
                for query in DELETES {
                    if tokio::time::Instant::now()>=deadline {return Ok(true);}
                    crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
                    let result=tokio::time::timeout_at(deadline.min(tokio::time::Instant::now()+Duration::from_secs(5)),sqlx::query(query).bind(self.database.namespace.as_ref()).bind(i64::from(BATCH_ROWS))
                        .execute(connection.as_mut().map_err(|_|unavailable())?)).await.map_err(|_|unavailable())?.map_err(|_|unavailable())?;
                    removed+=result.rows_affected();
                }
                if before==removed {break;}
            }
            if tokio::time::Instant::now()>=deadline {return Ok(true);}
            tokio::time::timeout_at(deadline.min(tokio::time::Instant::now()+Duration::from_secs(5)),sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM aegaeon.runtime_oidc_sessions WHERE namespace=$1 AND expires_at<=statement_timestamp())")
                .bind(self.database.namespace.as_ref()).fetch_one(connection.as_mut().map_err(|_|unavailable())?)).await.map_err(|_|unavailable())?.map_err(|_|unavailable())
        }.await;
        connection.release().await;
        (removed, result)
    }
}
