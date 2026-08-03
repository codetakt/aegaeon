use super::RequestObjectJtiStore;
use crate::config::{
    require_shared_runtime_store_url, valid_request_object_jti_ttl_secs, ConfigError,
    RuntimeRedisAtomicGroup, RuntimeStateNamespace,
};
#[cfg(test)]
use crate::middleware::InMemoryReplayStore;
use crate::middleware::{RedisReplayStore, ReplayStore};
use std::sync::Arc;
use std::time::Duration;

impl RequestObjectJtiStore {
    #[cfg(test)]
    fn new_process_local(ttl: Duration) -> Self {
        Self {
            replay_store: Arc::new(InMemoryReplayStore::new()),
            ttl,
        }
    }

    /// Construct a process-local Request Object JTI replay store for tests.
    ///
    /// Production code should use [`Self::try_from_shared_store_env_with_ttl_secs`] so shared
    /// runtime state is required and the TTL comes from the management configuration snapshot.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests(ttl: Duration) -> Self {
        Self::new_process_local(ttl)
    }

    /// Construct a store over an explicit replay backend.
    #[must_use]
    pub(crate) fn with_replay_store(ttl: Duration, replay_store: Arc<dyn ReplayStore>) -> Self {
        Self { replay_store, ttl }
    }

    pub fn try_from_shared_store_env_with_ttl_secs(
        ttl_secs: u64,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        if !valid_request_object_jti_ttl_secs(ttl_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "request_object_jti_ttl_seconds".to_string(),
                value: ttl_secs.to_string(),
                expectation: "a value in 1..=3600 seconds".to_string(),
            });
        }
        let ttl = Duration::from_secs(ttl_secs);
        let url = require_shared_runtime_store_url(
            "request-object jti replay store",
            "AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL",
        )?;
        RedisReplayStore::new_in_atomic_group(
            url.as_str(),
            runtime_state_namespace,
            RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
            "request-object-jti",
        )
        .map(|store| Self::with_replay_store(ttl, Arc::new(store)))
        .map_err(|err| ConfigError::InvalidValue {
            key: url.env_key().to_string(),
            value: "[redacted]".to_string(),
            reason: err.to_string(),
        })
    }

    #[must_use]
    pub fn replay_window(&self) -> Duration {
        self.ttl
    }
}
