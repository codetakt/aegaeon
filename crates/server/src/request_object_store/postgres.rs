use super::{RequestObjectBackend, RequestObjectJtiStore, RequestObjectReplayError};
use crate::authcode::store::PostgresGrantDatabase;
use crate::config::{valid_request_object_jti_ttl_secs, ConfigError};
use crate::dcr_persistence::admitted_connection::AdmittedConnection;
use std::time::Duration;

pub(super) fn retention_millis(ttl: Duration) -> Result<i64, RequestObjectReplayError> {
    let millis = ttl.as_nanos().div_ceil(1_000_000).max(1);
    if millis > 86_400_000 {
        return Err(RequestObjectReplayError::RetentionOverflow);
    }
    i64::try_from(millis).map_err(|_| RequestObjectReplayError::RetentionOverflow)
}

fn unavailable() -> RequestObjectReplayError {
    RequestObjectReplayError::BackendUnavailable(
        "Request Object replay database unavailable".into(),
    )
}

impl RequestObjectJtiStore {
    pub fn from_postgres(
        ttl_secs: u64,
        database: PostgresGrantDatabase,
    ) -> Result<Self, ConfigError> {
        if !valid_request_object_jti_ttl_secs(ttl_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "request_object_jti_ttl_seconds".into(),
                value: ttl_secs.to_string(),
                expectation: "a value in 1..=3600 seconds".into(),
            });
        }
        Ok(Self {
            backend: RequestObjectBackend::Postgres(database),
            ttl: Duration::from_secs(ttl_secs),
        })
    }

    pub async fn check_and_store_for_async(
        &self,
        client_id: String,
        jti: String,
        retention: Duration,
    ) -> Result<(), RequestObjectReplayError> {
        let RequestObjectBackend::Postgres(database) = &self.backend else {
            let store = self.clone();
            return crate::organizations::request_work::async_store::blocking(move || {
                store.check_and_store_for(&client_id, &jti, retention)
            })
            .await
            .map_err(|_| unavailable())?;
        };
        crate::organizations::lifecycle::proofs::ensure_allowed(
            crate::organizations::lifecycle::proofs::Kind::RequestObject,
        )
        .map_err(|_| RequestObjectReplayError::RecoveryDeferred)?;
        let ttl_ms = retention_millis(retention)?;
        let digest = aegaeon_crypto::hash::sha256_digest(
            &super::request_object_replay_key_material(&client_id, &jti),
        );
        let mut connection = AdmittedConnection::acquire(&database.pool)
            .await
            .map_err(|_| unavailable())?;
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            crate::organizations::request_work::async_store::admit_current_commit()
                .map_err(|_| unavailable())?;
            sqlx::query_scalar::<_, bool>(
                "SELECT aegaeon.record_runtime_request_object_jti($1,$2,$3)",
            )
            .bind(database.namespace.as_ref())
            .bind(digest.as_slice())
            .bind(ttl_ms)
            .fetch_one(connection.as_mut().map_err(|_| unavailable())?)
            .await
            .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| unavailable())
        .and_then(|result| result);
        connection.release().await;
        if result? {
            Ok(())
        } else {
            Err(RequestObjectReplayError::Replay)
        }
    }

    pub async fn cleanup_async(&self) -> Result<(), RequestObjectReplayError> {
        match &self.backend {
            RequestObjectBackend::Postgres(database) => crate::runtime_security_cleanup::cleanup(
                &database.pool,
                &database.namespace,
                crate::runtime_security_cleanup::Kind::RequestObject,
                crate::runtime_security_cleanup::PASS_BATCHES,
            )
            .await
            .map(|_| ())
            .map_err(|_| unavailable()),
            RequestObjectBackend::Replay(store) => {
                store.clone().cleanup_async().await.map_err(Into::into)
            }
        }
    }
}
