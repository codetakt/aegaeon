use super::*;

impl PostgresAuthCodeBackend {
    pub(in crate::authcode) async fn read(
        &self,
        code: &str,
    ) -> Result<Option<StoredAuthorizationCode>, AuthCodeStorageError> {
        let digest = sha256_digest(code.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), sqlx::query_as::<_,(String, Vec<u8>, i64)>(
            "SELECT payload,client_digest,(extract(epoch from expires_at)*1000000)::bigint FROM aegaeon.runtime_authorization_codes WHERE namespace=$1 AND token_digest=$2 AND expires_at>statement_timestamp()")
            .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).fetch_optional(connection.as_mut().map_err(|_| unavailable())?))
            .await.map_err(|_| unavailable()).and_then(|result| result.map_err(|_| unavailable()));
        connection.release().await;
        result?
            .map(|(payload, client, expiry)| decode(code, payload, &client, expiry))
            .transpose()
            .map(Option::flatten)
    }

    pub(in crate::authcode) async fn consume(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        let digest = sha256_digest(code.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit().map_err(|_| unavailable())?;
            sqlx::query_as::<_,(String,Vec<u8>,i64,bool)>("DELETE FROM aegaeon.runtime_authorization_codes WHERE namespace=$1 AND token_digest=$2 RETURNING payload,client_digest,(extract(epoch from expires_at)*1000000)::bigint,expires_at>clock_timestamp()")
                .bind(self.database.namespace.as_ref()).bind(digest.as_slice()).fetch_optional(connection.as_mut().map_err(|_| unavailable())?).await.map_err(|_| unavailable())
        }).await.map_err(|_| unavailable()).and_then(|result| result);
        connection.release().await;
        match result? {
            Some((payload, client, expiry, true)) => decode(code, payload, &client, expiry)
                .map(|stored| stored.map(|stored| stored.into_parts().0)),
            _ => Ok(None),
        }
    }
}

fn decode(
    requested: &str,
    payload: String,
    client: &[u8],
    expiry: i64,
) -> Result<Option<StoredAuthorizationCode>, AuthCodeStorageError> {
    let Some(stored) = StoredAuthorizationCode::decode(requested, payload)? else {
        return Ok(None);
    };
    if !crate::util::constant_time_eq(client, &sha256_digest(stored.code().client_id.as_bytes()))
        || expiry_micros(stored.code().expires_at)? != expiry
    {
        return Err(unavailable());
    }
    Ok(Some(stored))
}
