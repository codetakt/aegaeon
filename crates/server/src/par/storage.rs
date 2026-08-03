mod error;
#[cfg(test)]
mod in_memory;
mod record;
mod redis_store;
mod scripts;

pub(super) use error::ParStorageError;
#[cfg(test)]
pub(super) use in_memory::InMemoryParRequestStore;
pub(super) use redis_store::RedisParRequestStore;

use super::StoredParRequest;
use crate::authcode::store::ParAuthorizationCodeCommit;
use std::time::Duration;

pub(super) trait ParRequestStore: Send + Sync {
    fn insert(
        &self,
        request_uri: &str,
        stored: StoredParRequest,
        ttl: Duration,
    ) -> Result<(), ParStorageError>;
    fn load(&self, request_uri: &str) -> Result<Option<StoredParRequest>, ParStorageError>;
    fn reserve(
        &self,
        request_uri: &str,
        continuation: &str,
        ttl: Duration,
    ) -> Result<bool, ParStorageError>;
    fn reservation(&self, request_uri: &str) -> Result<Option<String>, ParStorageError>;
    fn authorization_code_commit_context(
        &self,
        _request_uri: &str,
        _expected_continuation: &str,
    ) -> Option<ParAuthorizationCodeCommit> {
        None
    }
    fn consume(&self, request_uri: &str) -> Result<Option<StoredParRequest>, ParStorageError>;
    fn remove(&self, request_uri: &str) -> Result<(), ParStorageError>;
    fn cleanup_expired(&self) -> Result<(), ParStorageError>;
}
