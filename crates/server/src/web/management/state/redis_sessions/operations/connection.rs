#[cfg(test)]
use std::sync::Arc;

use super::super::{
    error::ManagementSessionStorageError, keyspace::RedisManagementSessionKeyspace,
    RedisManagementSessionBackend,
};
use super::backend_unavailable;
use crate::config::RuntimeStateNamespace;

impl RedisManagementSessionBackend {
    pub(in crate::web::management::state) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ManagementSessionStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                keyspace: RedisManagementSessionKeyspace::from_runtime_namespace(namespace),
            })
            .map_err(|err| backend_unavailable(&err))
    }

    #[cfg(test)]
    pub(in crate::web::management) fn new_with_key(
        url: &str,
        key: impl Into<Arc<str>>,
    ) -> Result<Self, ManagementSessionStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                keyspace: RedisManagementSessionKeyspace::from_prefix(key),
            })
            .map_err(|err| backend_unavailable(&err))
    }

    pub(super) fn connection(&self) -> Result<redis::Connection, ManagementSessionStorageError> {
        self.client
            .get_connection()
            .map_err(|err| backend_unavailable(&err))
    }
}
