use super::{
    request_object_replay_key_material, RequestObjectJtiStore, RequestObjectReplayError,
    REQUEST_OBJECT_JTI_REPLAY_NAMESPACE,
};
use crate::authcode::store::RequestObjectJtiAuthorizationCodeCommit;
use crate::middleware::{RedisReplayCommitContext, ReplayEntry};
use std::time::Duration;

impl RequestObjectJtiStore {
    /// Record a `(client_id, jti)` pair for the supplied retention duration.
    ///
    /// # Errors
    ///
    /// Returns `RequestObjectReplayError::Replay` when the same `(client_id, jti)`
    /// pair is observed again before its retained replay entry expires,
    /// `RequestObjectReplayError::BackendUnavailable` when the store cannot
    /// confirm single-use semantics, or `RequestObjectReplayError::RetentionOverflow`
    /// when the replay retention cannot be represented.
    pub fn check_and_store_for(
        &self,
        client_id: &str,
        jti: &str,
        retention: Duration,
    ) -> Result<(), RequestObjectReplayError> {
        crate::organizations::lifecycle::proofs::ensure_allowed(
            crate::organizations::lifecycle::proofs::Kind::RequestObject,
        )
        .map_err(|_| RequestObjectReplayError::RecoveryDeferred)?;
        let retention = if retention.is_zero() {
            Duration::from_secs(1)
        } else {
            retention
        };
        let key_material = request_object_replay_key_material(client_id, jti);
        let super::RequestObjectBackend::Replay(replay_store) = &self.backend else {
            return Err(RequestObjectReplayError::BackendUnavailable(
                "PostgreSQL Request Object replay requires asynchronous access".into(),
            ));
        };
        replay_store
            .check_and_store(ReplayEntry::new(
                REQUEST_OBJECT_JTI_REPLAY_NAMESPACE,
                &key_material,
                retention,
            ))
            .map_err(Into::into)
    }

    pub(crate) fn authorization_code_commit_context_for(
        &self,
        client_id: &str,
        jti: &str,
        retention: Duration,
    ) -> Result<Option<RequestObjectJtiAuthorizationCodeCommit>, RequestObjectReplayError> {
        crate::organizations::lifecycle::proofs::ensure_allowed(
            crate::organizations::lifecycle::proofs::Kind::RequestObject,
        )
        .map_err(|_| RequestObjectReplayError::RecoveryDeferred)?;
        let retention = if retention.is_zero() {
            Duration::from_secs(1)
        } else {
            retention
        };
        let key_material = request_object_replay_key_material(client_id, jti);
        if let super::RequestObjectBackend::Postgres(database) = &self.backend {
            return Ok(Some(RequestObjectJtiAuthorizationCodeCommit::Postgres {
                database: database.clone(),
                digest: aegaeon_crypto::hash::sha256_digest(&key_material),
                client_digest: aegaeon_crypto::hash::sha256_digest(client_id.as_bytes()),
                ttl_ms: super::postgres::retention_millis(retention)?,
            }));
        }
        let super::RequestObjectBackend::Replay(replay_store) = &self.backend else {
            unreachable!()
        };
        replay_store
            .redis_commit_context(ReplayEntry::new(
                REQUEST_OBJECT_JTI_REPLAY_NAMESPACE,
                &key_material,
                retention,
            ))
            .map(|context| context.map(request_object_jti_commit_from_redis))
            .map_err(Into::into)
    }

    /// Record a `(client_id, jti)` pair for the store's configured replay window.
    ///
    /// # Errors
    ///
    /// Returns `RequestObjectReplayError::Replay` when the same `(client_id, jti)`
    /// pair is observed again within the configured TTL, propagating the same
    /// backend and retention errors as `check_and_store_for`.
    pub fn check_and_store(
        &self,
        client_id: &str,
        jti: &str,
    ) -> Result<(), RequestObjectReplayError> {
        self.check_and_store_for(client_id, jti, self.ttl)
    }
}

fn request_object_jti_commit_from_redis(
    context: RedisReplayCommitContext,
) -> RequestObjectJtiAuthorizationCodeCommit {
    RequestObjectJtiAuthorizationCodeCommit::Redis {
        url: context.url,
        key: context.key,
        ttl_ms: context.ttl_ms,
    }
}
