#[cfg(test)]
use crate::authcode::code_store::AuthCodeSnapshot;
#[cfg(test)]
use crate::authcode::code_store::InMemoryAuthCodeBackend;
use crate::authcode::code_store::{
    AuthCodeBackend, AuthCodeExchangeLock, AuthCodeRedisCommitContext, AuthCodeStorageError,
    AuthorizationCodeOneTimeInputCommit, RedisAuthCodeBackend, StoreCodeError,
};
use crate::authcode::types::AuthorizationCode;
#[cfg(test)]
use crate::config::DEFAULT_AUTHORIZATION_CODE_TTL_SECS;
use crate::config::{require_shared_runtime_store_url, ConfigError, RuntimeStateNamespace};
use std::sync::Arc;
use std::time::Duration;

/// Default process-local store TTL for tests (matches authorization code lifetime).
#[cfg(test)]
const DEFAULT_AUTH_CODE_STORE_TTL_SECS: u64 = DEFAULT_AUTHORIZATION_CODE_TTL_SECS;

fn log_auth_code_storage_error(error: &AuthCodeStorageError, operation: &str) {
    tracing::error!(error = %error, operation, "authorization code store operation failed");
}

fn auth_code_store_worker_error(error: tokio::task::JoinError) -> StoreCodeError {
    StoreCodeError::Storage(AuthCodeStorageError::BackendUnavailable(format!(
        "authorization code store worker failed: {error}"
    )))
}

/// Thread-safe authorization code store with single-use enforcement and TTL-based cleanup
#[derive(Clone)]
pub struct AuthCodeStore {
    pub(super) backend: Arc<dyn AuthCodeBackend>,
}

impl AuthCodeStore {
    #[cfg(test)]
    fn new_process_local_with_ttl(state_nonce_ttl: Duration) -> Self {
        Self {
            backend: Arc::new(InMemoryAuthCodeBackend::new(state_nonce_ttl)),
        }
    }

    /// Create a process-local authorization-code/state/nonce store for tests.
    ///
    /// Production code should use [`Self::try_from_shared_store_env_with_ttl`] so shared runtime
    /// state is required and the TTL comes from the management configuration snapshot.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local_with_ttl(Duration::from_secs(DEFAULT_AUTH_CODE_STORE_TTL_SECS))
    }

    /// Create a process-local authorization-code/state/nonce store with a custom TTL for tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_process_local_with_ttl_for_tests(state_nonce_ttl: Duration) -> Self {
        Self::new_process_local_with_ttl(state_nonce_ttl)
    }

    pub fn try_from_shared_store_env_with_ttl(
        state_nonce_ttl: Duration,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let url = require_shared_runtime_store_url(
            "authorization-code/state/nonce store",
            "AEGAEON_AUTH_CODE_REDIS_URL",
        )?;
        let backend =
            RedisAuthCodeBackend::new(url.as_str(), state_nonce_ttl, runtime_state_namespace)
                .map_err(|err| ConfigError::InvalidValue {
                    key: url.env_key().to_string(),
                    value: "[redacted]".to_string(),
                    reason: err.to_string(),
                })?;
        tracing::info!("authorization code store backend: redis");
        let backend = Arc::new(backend) as Arc<dyn AuthCodeBackend>;
        Ok(Self { backend })
    }

    /// Obtain a consistent snapshot of the current store
    #[must_use]
    #[cfg(test)]
    pub fn snapshot(&self) -> AuthCodeSnapshot {
        self.try_snapshot()
            .expect("test authorization code store snapshot should succeed")
    }

    /// Obtain a consistent snapshot of the current store, reporting backend failures.
    #[cfg(test)]
    pub fn try_snapshot(&self) -> Result<AuthCodeSnapshot, String> {
        self.backend.snapshot().map_err(|error| {
            let message = error.to_string();
            log_auth_code_storage_error(&error, "snapshot");
            message
        })
    }

    /// Inspect an authorization code without marking it as used, reporting backend failures.
    pub fn try_get_code(&self, code_str: &str) -> Result<Option<AuthorizationCode>, String> {
        self.backend.get_code(code_str).map_err(|error| {
            let message = error.to_string();
            log_auth_code_storage_error(&error, "get_code");
            message
        })
    }

    /// Inspect an authorization code on the blocking worker pool.
    pub async fn try_get_code_async(
        &self,
        code_str: String,
    ) -> Result<Option<AuthorizationCode>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_get_code(&code_str))
            .await
            .map_err(|err| format!("authorization code store worker failed: {err}"))?
    }

    /// Store an authorization code with state/nonce uniqueness enforcement.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied `state` or `nonce` was already
    /// observed within the configured TTL window.
    pub(in crate::authcode) fn store_code_typed(
        &self,
        code: AuthorizationCode,
    ) -> Result<String, StoreCodeError> {
        self.backend.store_code(code)
    }

    pub fn store_code(&self, code: AuthorizationCode) -> Result<String, String> {
        self.store_code_typed(code).map_err(|err| err.to_string())
    }

    pub(in crate::authcode) fn store_code_with_one_time_inputs_typed(
        &self,
        code: AuthorizationCode,
        one_time_inputs: AuthorizationCodeOneTimeInputCommit,
    ) -> Result<String, StoreCodeError> {
        self.backend
            .store_code_with_one_time_inputs(code, one_time_inputs)
    }

    /// Store an authorization code on the blocking worker pool.
    pub async fn store_code_async(&self, code: AuthorizationCode) -> Result<String, String> {
        self.store_code_typed_async(code)
            .await
            .map_err(|err| err.to_string())
    }

    pub(in crate::authcode) async fn store_code_typed_async(
        &self,
        code: AuthorizationCode,
    ) -> Result<String, StoreCodeError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.store_code_typed(code))
            .await
            .map_err(auth_code_store_worker_error)?
    }

    pub(in crate::authcode) async fn store_code_with_one_time_inputs_typed_async(
        &self,
        code: AuthorizationCode,
        one_time_inputs: AuthorizationCodeOneTimeInputCommit,
    ) -> Result<String, StoreCodeError> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.store_code_with_one_time_inputs_typed(code, one_time_inputs)
        })
        .await
        .map_err(auth_code_store_worker_error)?
    }

    /// Use authorization code with single-use enforcement, reporting backend failures.
    pub fn try_use_code(&self, code_str: &str) -> Result<Option<AuthorizationCode>, String> {
        self.backend.use_code(code_str).map_err(|error| {
            let message = error.to_string();
            log_auth_code_storage_error(&error, "use_code");
            message
        })
    }

    #[cfg(test)]
    pub(in crate::authcode) fn try_use_code_matching_payload(
        &self,
        code_str: &str,
        expected_payload: &str,
    ) -> Result<Option<AuthorizationCode>, String> {
        self.backend
            .use_code_if_payload_matches(code_str, expected_payload)
            .map_err(|error| {
                let message = error.to_string();
                log_auth_code_storage_error(&error, "use_code_if_payload_matches");
                message
            })
    }

    pub(in crate::authcode) fn redis_commit_context(
        &self,
        code_str: &str,
    ) -> Option<AuthCodeRedisCommitContext> {
        self.backend.redis_commit_context(code_str)
    }

    pub(in crate::authcode) fn acquire_exchange_lock(
        &self,
        code_str: &str,
    ) -> Result<AuthCodeExchangeLock, String> {
        self.backend
            .acquire_exchange_lock(code_str)
            .map_err(|error| {
                let message = error.to_string();
                log_auth_code_storage_error(&error, "acquire_exchange_lock");
                message
            })
    }

    pub(in crate::authcode) async fn acquire_exchange_lock_async(
        &self,
        code_str: String,
    ) -> Result<AuthCodeExchangeLock, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.acquire_exchange_lock(&code_str))
            .await
            .map_err(|err| format!("authorization code exchange lock worker failed: {err}"))?
    }

    /// Use an authorization code on the blocking worker pool.
    pub async fn try_use_code_async(
        &self,
        code_str: String,
    ) -> Result<Option<AuthorizationCode>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_use_code(&code_str))
            .await
            .map_err(|err| format!("authorization code store worker failed: {err}"))?
    }

    /// Clean up expired codes, states, and nonces
    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test authorization code cleanup should succeed");
    }

    /// Clean up expired codes, states, and nonces, reporting backend failures.
    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        self.backend.cleanup_expired().map_err(|error| {
            let message = error.to_string();
            log_auth_code_storage_error(&error, "cleanup_expired");
            message
        })
    }

    /// Get the current count of tracked states (for monitoring)
    #[must_use]
    #[cfg(test)]
    pub fn state_count(&self) -> usize {
        self.try_state_count()
            .expect("test authorization code state count should succeed")
    }

    /// Get the current count of tracked states (for monitoring), reporting backend failures.
    pub fn try_state_count(&self) -> Result<usize, String> {
        self.backend.state_count().map_err(|error| {
            let message = error.to_string();
            log_auth_code_storage_error(&error, "state_count");
            message
        })
    }

    /// Get the current count of tracked nonces (for monitoring)
    #[must_use]
    #[cfg(test)]
    pub fn nonce_count(&self) -> usize {
        self.try_nonce_count()
            .expect("test authorization code nonce count should succeed")
    }

    /// Get the current count of tracked nonces (for monitoring), reporting backend failures.
    pub fn try_nonce_count(&self) -> Result<usize, String> {
        self.backend.nonce_count().map_err(|error| {
            let message = error.to_string();
            log_auth_code_storage_error(&error, "nonce_count");
            message
        })
    }

    /// Verify state matches
    #[must_use]
    #[cfg(test)]
    pub fn verify_state(&self, request_state: Option<&str>, response_state: Option<&str>) -> bool {
        match (request_state, response_state) {
            (Some(s1), Some(s2)) => s1 == s2,
            (None, None) => true,
            _ => false,
        }
    }
}
