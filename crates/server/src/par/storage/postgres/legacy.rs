use super::*;
use crate::par::storage::ParRequestStore;

fn requires_async<T>() -> Result<T, ParStorageError> {
    Err(ParStorageError::BackendUnavailable(
        "PostgreSQL PAR requires asynchronous access".into(),
    ))
}

impl ParRequestStore for PostgresParRequestStore {
    fn postgres(&self) -> Option<&PostgresParRequestStore> {
        Some(self)
    }
    fn authorization_code_commit_context(
        &self,
        request_uri: &str,
        expected_continuation: &str,
    ) -> Option<crate::authcode::store::ParAuthorizationCodeCommit> {
        Some(
            crate::authcode::store::ParAuthorizationCodeCommit::Postgres {
                database: self.database.clone(),
                request_digest: sha256_digest(request_uri.as_bytes()),
                expected_continuation: expected_continuation.to_owned(),
            },
        )
    }
    fn insert(&self, _: &str, _: StoredParRequest, _: Duration) -> Result<(), ParStorageError> {
        requires_async()
    }
    fn load(&self, _: &str) -> Result<Option<StoredParRequest>, ParStorageError> {
        requires_async()
    }
    fn reserve(&self, _: &str, _: &str, _: Duration) -> Result<bool, ParStorageError> {
        requires_async()
    }
    fn reservation(&self, _: &str) -> Result<Option<String>, ParStorageError> {
        requires_async()
    }
    fn consume(&self, _: &str) -> Result<Option<StoredParRequest>, ParStorageError> {
        requires_async()
    }
    fn remove(&self, _: &str) -> Result<(), ParStorageError> {
        requires_async()
    }
    fn cleanup_expired(&self) -> Result<(), ParStorageError> {
        requires_async()
    }
}
