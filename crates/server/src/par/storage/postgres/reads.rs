use super::*;

impl PostgresParRequestStore {
    pub(in crate::par) async fn load(
        &self,
        request_uri: &str,
    ) -> Result<Option<StoredParRequest>, ParStorageError> {
        let digest = sha256_digest(request_uri.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),sqlx::query_as::<_,(Vec<u8>,String,i64,Option<String>,bool)>("SELECT client_digest,payload,extract(epoch from expires_at)::bigint,continuation,continuation IS NULL OR reservation_payload_digest=sha256(convert_to(payload,'UTF8')) FROM aegaeon.runtime_par_requests WHERE namespace=$1 AND token_digest=$2 AND expires_at>statement_timestamp()")
            .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).fetch_optional(connection.as_mut().map_err(|_|unavailable())?))
            .await.map_err(|_|unavailable()).and_then(|result| result.map_err(|_|unavailable()));
        connection.release().await;
        result?
            .map(|(client, payload, expiry, continuation, intact)| {
                if !intact {
                    return Err(unavailable());
                }
                decode(&client, &payload, expiry, continuation)
            })
            .transpose()
            .map(Option::flatten)
    }

    pub(in crate::par) async fn consume(
        &self,
        request_uri: &str,
    ) -> Result<Option<StoredParRequest>, ParStorageError> {
        let digest = sha256_digest(request_uri.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_|unavailable())?;
            sqlx::query_as::<_,(Vec<u8>,String,i64,bool)>("DELETE FROM aegaeon.runtime_par_requests WHERE namespace=$1 AND token_digest=$2 RETURNING client_digest,payload,extract(epoch from expires_at)::bigint,expires_at>clock_timestamp()")
                .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).fetch_optional(connection.as_mut().map_err(|_|unavailable())?).await.map_err(|_|unavailable())
        }).await.map_err(|_|unavailable()).and_then(|result|result);
        connection.release().await;
        match result? {
            Some((client, payload, expiry, true)) => decode(&client, &payload, expiry, None),
            _ => Ok(None),
        }
    }
}
