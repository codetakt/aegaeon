//! Secure storage for authorization codes and tokens with snapshot consistency

mod code_facade;
mod grant_commit;
mod redis_backend;
mod redis_support;
mod refresh_rotation;
mod revocation;
mod token_consistency;
mod token_outcome;
mod token_records;
mod token_state;

pub use self::code_facade::AuthCodeStore;
pub(in crate::authcode) use self::grant_commit::{
    AuthorizationCodeGrantCommit, AUTHORIZATION_CODE_GRANT_CODE_MISSING,
};
use self::redis_backend::RedisTokenStoreBackend;
#[cfg(test)]
use self::token_consistency::access_token_expired_at;
use self::token_outcome::TokenRevocationOutcome;
pub use self::token_outcome::{ClientBoundRevocationOutcome, RefreshRotationError};
pub use self::token_state::TokenSnapshot;
#[cfg(test)]
use self::token_state::TokenStoreState;
use self::token_state::TokenStoreStorageError;
pub use super::code_store::AuthCodeSnapshot;
pub(crate) use super::code_store::{
    AuthorizationCodeOneTimeInputCommit, ParAuthorizationCodeCommit,
    RequestObjectJtiAuthorizationCodeCommit,
};
use super::types::AccessToken;
use crate::config::{require_shared_runtime_store_url, ConfigError, RuntimeStateNamespace};
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;
use std::time::SystemTime;

const TOKEN_STORE_REDIS_URL_ENV: &str = "AEGAEON_TOKEN_STORE_REDIS_URL";

/// Expose the authorization-code expiry predicate for spec-oracle differential tests.
#[doc(hidden)]
#[must_use]
pub fn authorization_code_not_expired_for_spec_oracle(
    current_time_epoch_secs: u64,
    expires_at_epoch_secs: u64,
) -> bool {
    current_time_epoch_secs < expires_at_epoch_secs
}

#[cfg(test)]
fn token_store_lock_error(
    error: impl std::fmt::Display,
    operation: &str,
    lock_kind: &str,
) -> String {
    let error =
        TokenStoreStorageError::BackendUnavailable(format!("{lock_kind} lock poisoned: {error}"));
    token_storage_error_message(&error, operation)
}

#[cfg(test)]
fn read_lock<'a, T>(
    lock: &'a RwLock<T>,
    operation: &'static str,
) -> Result<RwLockReadGuard<'a, T>, String> {
    lock.read()
        .map_err(|err| token_store_lock_error(err, operation, "read"))
}

#[cfg(test)]
fn write_lock<'a, T>(
    lock: &'a RwLock<T>,
    operation: &'static str,
) -> Result<RwLockWriteGuard<'a, T>, String> {
    lock.write()
        .map_err(|err| token_store_lock_error(err, operation, "write"))
}

#[derive(Clone)]
enum TokenStoreBackend {
    #[cfg(test)]
    InMemory(Arc<RwLock<TokenStoreState>>),
    Redis(RedisTokenStoreBackend),
}

fn log_token_storage_error(error: &TokenStoreStorageError, operation: &str) {
    tracing::error!(error = %error, operation, "token store operation failed");
}

fn token_storage_error_message(error: &TokenStoreStorageError, operation: &str) -> String {
    let message = error.to_string();
    log_token_storage_error(error, operation);
    message
}

/// Token store with expiration and revocation support
#[derive(Clone)]
pub struct TokenStore {
    backend: TokenStoreBackend,
}

impl TokenStore {
    #[cfg(test)]
    fn new_process_local() -> Self {
        Self {
            backend: TokenStoreBackend::InMemory(Arc::new(RwLock::new(TokenStoreState::default()))),
        }
    }

    /// Create a process-local token/revocation store for tests.
    ///
    /// Production code should use [`Self::try_from_shared_store_env`] so shared runtime state is
    /// required.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local()
    }

    pub fn try_from_shared_store_env(
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let url =
            require_shared_runtime_store_url("token/revocation store", TOKEN_STORE_REDIS_URL_ENV)?;
        let backend =
            RedisTokenStoreBackend::new(url.as_str(), runtime_state_namespace).map_err(|err| {
                ConfigError::InvalidValue {
                    key: url.env_key().to_string(),
                    value: "[redacted]".to_string(),
                    reason: err.to_string(),
                }
            })?;
        tracing::info!("token store backend: redis");
        Ok(Self {
            backend: TokenStoreBackend::Redis(backend),
        })
    }

    #[cfg(test)]
    fn try_with_state<R>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&TokenStoreState) -> R,
    ) -> Result<R, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let state = read_lock(state, operation)?;
                Ok(f(&state))
            }
            TokenStoreBackend::Redis(backend) => backend
                .load_state()
                .map(|state| f(&state))
                .map_err(|error| token_storage_error_message(&error, operation)),
        }
    }

    #[cfg(test)]
    fn try_mutate_state<R>(
        &self,
        operation: &'static str,
        mut f: impl FnMut(&mut TokenStoreState) -> R,
    ) -> Result<R, String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, operation)?;
                Ok(f(&mut state))
            }
            TokenStoreBackend::Redis(backend) => backend
                .mutate_state(f)
                .map_err(|error| token_storage_error_message(&error, operation)),
        }
    }

    fn access_token_revocation_expires_at(
        token: &AccessToken,
        now: SystemTime,
    ) -> Option<SystemTime> {
        token
            .created_at
            .checked_add(Duration::from_secs(token.expires_in))
            .or_else(|| {
                now.checked_add(Duration::from_secs(
                    crate::config::MAX_ACCESS_TOKEN_TTL_SECS,
                ))
            })
    }

    #[cfg(test)]
    fn insert_access_revoked_locked(
        state: &mut TokenStoreState,
        token_str: impl Into<String>,
        token: &AccessToken,
        now: SystemTime,
    ) {
        if let Some(expires_at) = Self::access_token_revocation_expires_at(token, now) {
            Self::insert_revoked_locked(state, token_str, expires_at, now);
        }
    }

    #[cfg(test)]
    fn is_revoked_locked(state: &TokenStoreState, token_str: &str, now: SystemTime) -> bool {
        state
            .revoked_tokens
            .get(token_str)
            .is_some_and(|expires_at| *expires_at > now)
    }

    #[cfg(test)]
    fn insert_revoked_locked(
        state: &mut TokenStoreState,
        token_str: impl Into<String>,
        expires_at: SystemTime,
        now: SystemTime,
    ) {
        let token_str = token_str.into();
        if expires_at > now {
            state
                .revoked_tokens
                .entry(token_str)
                .and_modify(|current| {
                    if *current < expires_at {
                        *current = expires_at;
                    }
                })
                .or_insert(expires_at);
        } else {
            state.revoked_tokens.remove(&token_str);
        }
    }

    #[cfg(test)]
    fn cleanup_revoked_locked(state: &mut TokenStoreState, now: SystemTime) -> usize {
        let before = state.revoked_tokens.len();
        state
            .revoked_tokens
            .retain(|_, expires_at| *expires_at > now);
        before.saturating_sub(state.revoked_tokens.len())
    }

    #[cfg(test)]
    fn cleanup_expired_locked(state: &mut TokenStoreState, now: SystemTime) {
        let before_access = state.access_tokens.len();
        state
            .access_tokens
            .retain(|_, token| !access_token_expired_at(token, now));

        let before_refresh = state.refresh_tokens.len();
        let before_refresh_children = state.refresh_children.len();
        let before_refresh_successors = state.refresh_successors.len();
        let before_bearer_meta = state.bearer_meta.len();
        let expired_refresh: HashSet<String> = state
            .refresh_tokens
            .iter()
            .filter(|(_, token)| now >= token.expires_at)
            .map(|(key, _)| key.clone())
            .collect();
        state
            .refresh_tokens
            .retain(|_, token| now < token.expires_at);
        for refresh in expired_refresh {
            state.refresh_children.remove(&refresh);
        }
        let live_refresh: HashSet<String> = state.refresh_tokens.keys().cloned().collect();
        state.refresh_successors.retain(|previous, successor| {
            live_refresh.contains(previous) && live_refresh.contains(successor)
        });
        state.bearer_meta.retain(|_, meta| now < meta.expires_at);

        let before_revoked = state.revoked_tokens.len();
        Self::cleanup_revoked_locked(state, now);

        if before_access != state.access_tokens.len()
            || before_refresh != state.refresh_tokens.len()
            || before_refresh_children != state.refresh_children.len()
            || before_refresh_successors != state.refresh_successors.len()
            || before_bearer_meta != state.bearer_meta.len()
            || before_revoked != state.revoked_tokens.len()
        {
            state.version = state.version.saturating_add(1);
        }
    }

    /// Clean up expired tokens, reporting backend failures.
    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            TokenStoreBackend::InMemory(state) => {
                let mut state = write_lock(state, "cleanup_expired")?;
                Self::cleanup_expired_locked(&mut state, SystemTime::now());
                Ok(())
            }
            TokenStoreBackend::Redis(backend) => backend
                .cleanup_expired()
                .map_err(|error| token_storage_error_message(&error, "cleanup_expired")),
        }
    }

    /// Clean up expired tokens.
    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test token cleanup should succeed");
    }
}

#[cfg(test)]
mod tests;
