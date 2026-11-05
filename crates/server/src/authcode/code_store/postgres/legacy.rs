use super::*;
use crate::authcode::code_store::{AuthCodeBackend, AuthCodeExchangeLock};

fn requires_async<T>() -> Result<T, AuthCodeStorageError> {
    Err(AuthCodeStorageError::BackendUnavailable(
        "PostgreSQL authorization codes require asynchronous access".into(),
    ))
}

impl AuthCodeBackend for PostgresAuthCodeBackend {
    fn postgres(&self) -> Option<&PostgresAuthCodeBackend> {
        Some(self)
    }
    fn acquire_exchange_lock(&self, _: &str) -> Result<AuthCodeExchangeLock, AuthCodeStorageError> {
        requires_async()
    }
    #[cfg(test)]
    fn snapshot(
        &self,
    ) -> Result<crate::authcode::code_store::AuthCodeSnapshot, AuthCodeStorageError> {
        requires_async()
    }
    fn get_code(&self, _: &str) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        requires_async()
    }
    fn get_code_for_exchange(
        &self,
        _: &str,
    ) -> Result<Option<StoredAuthorizationCode>, AuthCodeStorageError> {
        requires_async()
    }
    fn store_code(&self, _: AuthorizationCode) -> Result<String, StoreCodeError> {
        requires_async().map_err(Into::into)
    }
    fn use_code(&self, _: &str) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        requires_async()
    }
    fn cleanup_expired(&self) -> Result<(), AuthCodeStorageError> {
        requires_async()
    }
    fn state_count(&self) -> Result<usize, AuthCodeStorageError> {
        requires_async()
    }
    fn nonce_count(&self) -> Result<usize, AuthCodeStorageError> {
        requires_async()
    }
}
