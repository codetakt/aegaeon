use super::*;
use crate::runtime_security_cleanup::{BATCH_ROWS, PASS_BATCHES};

// No cascading deletion: each statement has its own bounded set of locked rows.
const DELETES: [&str;3] = [
    "DELETE FROM aegaeon.runtime_token_capabilities WHERE ctid IN (SELECT ctid FROM aegaeon.runtime_token_capabilities WHERE namespace=$1 AND expires_us<=floor(extract(epoch from statement_timestamp())*1000000)::bigint ORDER BY expires_us,token_digest LIMIT $2 FOR UPDATE SKIP LOCKED)",
    "DELETE FROM aegaeon.runtime_exchange_roots WHERE ctid IN (SELECT r.ctid FROM aegaeon.runtime_exchange_roots r WHERE r.namespace=$1 AND r.expires_us<=floor(extract(epoch from statement_timestamp())*1000000)::bigint AND NOT EXISTS(SELECT 1 FROM aegaeon.runtime_token_capabilities c WHERE (c.namespace,c.root_id)=(r.namespace,r.id)) ORDER BY r.expires_us,r.id LIMIT $2 FOR UPDATE OF r SKIP LOCKED)",
    "DELETE FROM aegaeon.runtime_refresh_families WHERE ctid IN (SELECT f.ctid FROM aegaeon.runtime_refresh_families f WHERE f.namespace=$1 AND f.expires_us<=floor(extract(epoch from statement_timestamp())*1000000)::bigint AND NOT EXISTS(SELECT 1 FROM aegaeon.runtime_token_capabilities c WHERE (c.namespace,c.family_id)=(f.namespace,f.id)) AND NOT EXISTS(SELECT 1 FROM aegaeon.runtime_exchange_roots r WHERE (r.namespace,r.family_id)=(f.namespace,f.id)) ORDER BY f.expires_us,f.id LIMIT $2 FOR UPDATE OF f SKIP LOCKED)",
];
const REMAINING:&str="SELECT EXISTS(SELECT 1 FROM aegaeon.runtime_token_capabilities WHERE namespace=$1 AND expires_us<=floor(extract(epoch from statement_timestamp())*1000000)::bigint) OR EXISTS(SELECT 1 FROM aegaeon.runtime_exchange_roots WHERE namespace=$1 AND expires_us<=floor(extract(epoch from statement_timestamp())*1000000)::bigint) OR EXISTS(SELECT 1 FROM aegaeon.runtime_refresh_families WHERE namespace=$1 AND expires_us<=floor(extract(epoch from statement_timestamp())*1000000)::bigint)";

impl PostgresTokenStoreBackend {
    pub(in crate::authcode::store) async fn cleanup(&self) -> Result<(), String> {
        let result = self.cleanup_inner().await;
        crate::runtime_security_cleanup::record_token_cleanup(
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
        let result = async {
            for _ in 0..PASS_BATCHES {
                let before = removed;
                for query in DELETES {
                    if tokio::time::Instant::now() >= deadline {
                        return Ok(true);
                    }
                    crate::organizations::request_work::async_store::admit_current_commit()
                        .map_err(|_| unavailable())?;
                    let result = tokio::time::timeout_at(
                        deadline.min(tokio::time::Instant::now() + Duration::from_secs(5)),
                        sqlx::query(query)
                            .bind(self.database.namespace.as_ref())
                            .bind(i64::from(BATCH_ROWS))
                            .execute(connection.as_mut().map_err(|_| unavailable())?),
                    )
                    .await
                    .map_err(|_| unavailable())?
                    .map_err(|_| unavailable())?;
                    removed += result.rows_affected();
                }
                if before == removed {
                    break;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(true);
            }
            tokio::time::timeout_at(
                deadline.min(tokio::time::Instant::now() + Duration::from_secs(5)),
                sqlx::query_scalar::<_, bool>(REMAINING)
                    .bind(self.database.namespace.as_ref())
                    .fetch_one(connection.as_mut().map_err(|_| unavailable())?),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())
        }
        .await;
        connection.release().await;
        (removed, result)
    }
}
