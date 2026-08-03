use super::redis_state::RedisAuthSessionKeyspace;
use crate::config::RuntimeStateNamespace;
#[cfg(test)]
use std::sync::Arc;
use thiserror::Error;

#[path = "redis_backend/codec.rs"]
mod codec;
#[path = "redis_backend/operations.rs"]
mod operations;
#[path = "redis_backend/scripts.rs"]
mod scripts;

#[derive(Clone)]
pub(super) struct RedisAuthSessionBackend {
    client: redis::Client,
    keyspace: RedisAuthSessionKeyspace,
}

#[derive(Debug, Error)]
pub(super) enum AuthSessionStorageError {
    #[error("auth session store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("auth session store retention cannot be represented")]
    RetentionOverflow,
}

impl RedisAuthSessionBackend {
    pub(super) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, AuthSessionStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                keyspace: RedisAuthSessionKeyspace::from_runtime_namespace(namespace),
            })
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(super) fn new_with_prefix(
        url: &str,
        prefix: impl Into<Arc<str>>,
    ) -> Result<Self, AuthSessionStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                keyspace: RedisAuthSessionKeyspace::from_test_prefix(prefix),
            })
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, AuthSessionStorageError> {
        self.client
            .get_connection()
            .map_err(|err| AuthSessionStorageError::BackendUnavailable(err.to_string()))
    }
}
