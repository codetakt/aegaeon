use super::{record::StoredParRequestRecord, ParStorageError};
use crate::authcode::store::PostgresGrantDatabase;
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use crate::par::StoredParRequest;
use aegaeon_crypto::hash::sha256_digest;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod legacy;
mod reads;
#[cfg(test)]
mod tests;

pub(in crate::par) struct PostgresParRequestStore {
    database: PostgresGrantDatabase,
}

pub(in crate::par) enum Lookup {
    Missing,
    ClientMismatch,
    Found(Box<StoredParRequest>),
}

fn unavailable() -> ParStorageError {
    ParStorageError::BackendUnavailable("PostgreSQL PAR state unavailable".into())
}

fn encode_deadline(value: SystemTime) -> Result<String, ParStorageError> {
    let seconds = value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ParStorageError::ExpiryOutOfRange)?
        .as_secs();
    let seconds = i64::try_from(seconds).map_err(|_| ParStorageError::ExpiryOutOfRange)?;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| ParStorageError::ExpiryOutOfRange)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| ParStorageError::ExpiryOutOfRange)
}

impl PostgresParRequestStore {
    pub(in crate::par) fn new(database: PostgresGrantDatabase) -> Self {
        Self { database }
    }

    #[cfg(test)]
    pub(in crate::par) async fn insert(
        &self,
        request_uri: &str,
        stored: StoredParRequest,
    ) -> Result<(), ParStorageError> {
        self.insert_with_jti(request_uri, stored, None).await
    }

    pub(in crate::par) async fn insert_with_jti(
        &self,
        request_uri: &str,
        stored: StoredParRequest,
        jti: Option<crate::authcode::store::RequestObjectJtiAuthorizationCodeCommit>,
    ) -> Result<(), ParStorageError> {
        let (jti_digest, jti_ms) = match &jti {
            Some(crate::authcode::store::RequestObjectJtiAuthorizationCodeCommit::Postgres {
                database,
                digest,
                client_digest,
                ttl_ms,
            }) if self.database.same_database(database)
                && crate::util::constant_time_eq(
                    client_digest,
                    &sha256_digest(stored.client_id.as_bytes()),
                ) =>
            {
                (Some(digest.as_slice()), Some(*ttl_ms))
            }
            None => (None, None),
            Some(_) => return Err(unavailable()),
        };
        if stored.client_id.is_empty()
            || stored.request.client_id != stored.client_id
            || stored.expires_at <= SystemTime::now()
        {
            return Err(unavailable());
        }
        let expiry = encode_deadline(stored.expires_at)?;
        let client = sha256_digest(stored.client_id.as_bytes());
        let digest = sha256_digest(request_uri.as_bytes());
        let payload = serde_json::to_string(&StoredParRequestRecord::try_from(stored)?)
            .map_err(|_| unavailable())?;
        if payload.len() > 1_048_576 {
            return Err(unavailable());
        }
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_scalar::<_, i32>(
                "SELECT aegaeon.publish_runtime_par($1,$2,$3,$4,$5::text::timestamptz,$6,$7)",
            )
            .bind(self.database.namespace.as_ref())
            .bind(digest.as_slice())
            .bind(client.as_slice())
            .bind(payload)
            .bind(expiry)
            .bind(jti_digest)
            .bind(jti_ms)
            .fetch_one(connection.as_mut().map_err(|_| unavailable())?)
            .await
            .map_err(|_| unavailable())
            .and_then(|result| match result {
                0 => Ok(()),
                3 => Err(ParStorageError::RequestObjectReplay),
                _ => Err(unavailable()),
            })
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result
    }

    pub(in crate::par) async fn reserve(
        &self,
        request_uri: &str,
        client_id: &str,
        continuation: &str,
    ) -> Result<Lookup, ParStorageError> {
        let digest = sha256_digest(request_uri.as_bytes());
        let client = sha256_digest(client_id.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_as::<_, (i32, Option<String>, Option<i64>)>(
                "SELECT outcome,payload,expiry FROM aegaeon.reserve_runtime_par($1,$2,$3,$4)",
            )
            .bind(self.database.namespace.as_ref())
            .bind(digest.as_slice())
            .bind(client.as_slice())
            .bind(continuation)
            .fetch_one(connection.as_mut().map_err(|_| unavailable())?)
            .await
            .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        match result? {
            (0, Some(payload), Some(expiry)) => {
                Ok(
                    decode(&client, &payload, expiry, Some(continuation.to_owned()))?
                        .map_or(Lookup::Missing, |value| Lookup::Found(Box::new(value))),
                )
            }
            (1, None, None) => Ok(Lookup::Missing),
            (2, None, None) => Ok(Lookup::ClientMismatch),
            _ => Err(unavailable()),
        }
    }

    #[cfg(test)]
    pub(in crate::par) async fn remove(&self, request_uri: &str) -> Result<(), ParStorageError> {
        let digest = sha256_digest(request_uri.as_bytes());
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query(
                "DELETE FROM aegaeon.runtime_par_requests WHERE namespace=$1 AND token_digest=$2",
            )
            .bind(self.database.namespace.as_ref())
            .bind(digest.as_slice())
            .execute(connection.as_mut().map_err(|_| unavailable())?)
            .await
            .map(|_| ())
            .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        result
    }

    pub(in crate::par) async fn cleanup(&self) -> Result<(), ParStorageError> {
        crate::runtime_security_cleanup::cleanup(
            &self.database.pool,
            &self.database.namespace,
            crate::runtime_security_cleanup::Kind::Par,
            crate::runtime_security_cleanup::PASS_BATCHES,
        )
        .await
        .map(|_| ())
        .map_err(|_| unavailable())
    }
}

fn decode(
    client: &[u8],
    payload: &str,
    expiry: i64,
    continuation: Option<String>,
) -> Result<Option<StoredParRequest>, ParStorageError> {
    let record: StoredParRequestRecord =
        serde_json::from_str(payload).map_err(|_| unavailable())?;
    let mut stored = StoredParRequest::try_from(record)?;
    let stored_expiry = stored
        .expires_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unavailable())?
        .as_secs();
    if !crate::util::constant_time_eq(client, &sha256_digest(stored.client_id.as_bytes()))
        || stored.request.client_id != stored.client_id
        || u64::try_from(expiry).map_err(|_| unavailable())? != stored_expiry
    {
        return Err(unavailable());
    }
    if stored.expires_at <= SystemTime::now() {
        return Ok(None);
    }
    stored.authorize_continuation = continuation;
    Ok(Some(stored))
}
