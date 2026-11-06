use super::{
    AuthCodeStorageError, AuthorizationCode, AuthorizationCodeOneTimeInputCommit, StoreCodeError,
    StoredAuthorizationCode,
};
use crate::authcode::store::PostgresGrantDatabase;
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use aegaeon_crypto::hash::sha256_digest;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod issue;
mod legacy;
mod reads;
#[cfg(test)]
mod tests;

pub(in crate::authcode) struct PostgresAuthCodeBackend {
    pub(in crate::authcode) database: PostgresGrantDatabase,
    observation_ms: i64,
}

fn unavailable() -> AuthCodeStorageError {
    AuthCodeStorageError::BackendUnavailable("authorization code database unavailable".into())
}

fn expiry_micros(value: SystemTime) -> Result<i64, AuthCodeStorageError> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_micros()).ok())
        .ok_or(AuthCodeStorageError::RetentionOverflow)
}

impl PostgresAuthCodeBackend {
    pub(in crate::authcode) async fn observation_counts(
        &self,
    ) -> Result<(usize, usize), AuthCodeStorageError> {
        let mut connection = AdmittedConnection::acquire(&self.database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result=tokio::time::timeout(Duration::from_secs(5),sqlx::query_as::<_,(i64,i64)>("SELECT count(*) FILTER(WHERE kind=0),count(*) FILTER(WHERE kind=1) FROM aegaeon.runtime_authorization_observations WHERE namespace=$1 AND expires_at>statement_timestamp()")
            .bind(self.database.namespace.as_ref()).fetch_one(connection.as_mut().map_err(|_|unavailable())?)).await.map_err(|_|unavailable()).and_then(|r|r.map_err(|_|unavailable()));
        connection.release().await;
        let (states, nonces) = result?;
        Ok((
            usize::try_from(states).map_err(|_| unavailable())?,
            usize::try_from(nonces).map_err(|_| unavailable())?,
        ))
    }

    pub(in crate::authcode) fn new(
        database: PostgresGrantDatabase,
        ttl: Duration,
    ) -> Result<Self, AuthCodeStorageError> {
        let observation_ms = i64::try_from(ttl.as_nanos().div_ceil(1_000_000))
            .map_err(|_| AuthCodeStorageError::RetentionOverflow)?;
        if !(1..=86_400_000).contains(&observation_ms) {
            return Err(AuthCodeStorageError::RetentionOverflow);
        }
        Ok(Self {
            database,
            observation_ms,
        })
    }

    pub(in crate::authcode) async fn cleanup(&self) -> Result<(), AuthCodeStorageError> {
        for kind in [
            crate::runtime_security_cleanup::Kind::AuthorizationCode,
            crate::runtime_security_cleanup::Kind::AuthorizationObservation,
        ] {
            crate::runtime_security_cleanup::cleanup(
                &self.database.pool,
                &self.database.namespace,
                kind,
                crate::runtime_security_cleanup::PASS_BATCHES,
            )
            .await
            .map_err(|_| unavailable())?;
        }
        Ok(())
    }
}
