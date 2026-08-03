//! Pushed Authorization Requests storage and request materialization.
//!
//! PAR creation validates the pushed request against the client policy known at
//! creation time. Later `request_uri` reservation only checks storage state,
//! expiry, single-use reservation, continuation, and client binding; the
//! front-channel authorization validator remains responsible for applying the
//! current client policy to the materialized request.

#[cfg(test)]
use std::collections::HashMap;
use std::sync::{atomic::AtomicU64, Arc};
#[cfg(test)]
use std::sync::{RwLock, RwLockWriteGuard};
use std::time::{Duration, SystemTime};

use crate::authcode::store::ParAuthorizationCodeCommit;
#[cfg(test)]
use crate::client_registry::ClientSecretCredential;
use crate::config::{
    require_shared_runtime_store_url, valid_par_expires_in_secs, ConfigError,
    RuntimeStateNamespace, DEFAULT_PAR_EXPIRES_IN_SECS,
};

#[cfg(test)]
mod client_registry;
mod endpoint;
mod request_uri;
mod state;
mod storage;
mod types;
mod validation;
pub use endpoint::ParEndpoint;
pub use state::ParStateError;
#[cfg(test)]
use state::{try_read_lock, try_write_lock};
#[cfg(test)]
use storage::InMemoryParRequestStore;
use storage::{ParRequestStore, ParStorageError, RedisParRequestStore};
#[cfg(test)]
pub use types::Client;
use types::ValidatedParRequest;
pub use types::{ParError, ParRequest, ParResponse, ReservedParRequest, StoredParRequest};

/// PAR store for managing request URIs
pub struct ParStore {
    request_store: Arc<dyn ParRequestStore>,
    #[cfg(test)]
    clients: Arc<RwLock<HashMap<String, Client>>>,
    #[cfg(test)]
    client_secret_credentials: Arc<RwLock<HashMap<String, Vec<ClientSecretCredential>>>>,
    expires_in: AtomicU64,
}

#[cfg(test)]
pub(crate) struct ParRuntimeClientProjectionWriteGuard<'a> {
    clients: RwLockWriteGuard<'a, HashMap<String, Client>>,
    client_secret_credentials: RwLockWriteGuard<'a, HashMap<String, Vec<ClientSecretCredential>>>,
}

fn remaining_ttl(expires_at: SystemTime) -> Option<Duration> {
    expires_at.duration_since(SystemTime::now()).ok()
}

fn storage_error_to_par_error(error: &ParStorageError) -> ParError {
    tracing::error!(error = %error, "PAR request store operation failed");
    ParError {
        error: "server_error".to_string(),
        error_description: Some("PAR request store backend unavailable".to_string()),
    }
}

#[cfg(test)]
fn state_error_to_par_error(error: &ParStateError) -> ParError {
    tracing::error!(error = %error, "PAR runtime state operation failed");
    ParError {
        error: "server_error".to_string(),
        error_description: Some("PAR runtime state unavailable".to_string()),
    }
}

impl ParStore {
    /// Maximum allowed PAR TTL (10 minutes). Prevents unbounded lifetimes.
    #[cfg(test)]
    const MAX_PAR_EXPIRES_IN: u64 = crate::config::MAX_PAR_EXPIRES_IN_SECS;
    const DEFAULT_EXPIRES_IN: u64 = DEFAULT_PAR_EXPIRES_IN_SECS;

    const fn valid_expires_in(value: u64) -> bool {
        valid_par_expires_in_secs(value)
    }

    /// Create a process-local PAR store for tests and fuzzing.
    ///
    /// Production code should use [`Self::try_new_from_shared_store_env_with_expires_in`] so shared
    /// runtime state is required and the TTL comes from the management configuration snapshot.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::with_expires_in(Self::DEFAULT_EXPIRES_IN)
    }

    pub fn try_new_from_shared_store_env_with_expires_in(
        expires_in: u64,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        if !Self::valid_expires_in(expires_in) {
            return Err(ConfigError::InvalidNumberRange {
                key: "par_expires_in_seconds".to_string(),
                value: expires_in.to_string(),
                expectation: "a value in 1..=600 seconds".to_string(),
            });
        }
        let url =
            require_shared_runtime_store_url("PAR request_uri store", "AEGAEON_PAR_REDIS_URL")?;
        let store =
            RedisParRequestStore::new(url.as_str(), runtime_state_namespace).map_err(|err| {
                ConfigError::InvalidValue {
                    key: url.env_key().to_string(),
                    value: "[redacted]".to_string(),
                    reason: err.to_string(),
                }
            })?;
        tracing::info!("PAR request_uri store backend: redis");
        let request_store = Arc::new(store) as Arc<dyn ParRequestStore>;
        Ok(Self::with_request_store(expires_in, request_store))
    }

    #[cfg(test)]
    fn with_expires_in(expires_in: u64) -> Self {
        Self::with_request_store(expires_in, Arc::new(InMemoryParRequestStore::new()))
    }

    fn with_request_store(expires_in: u64, request_store: Arc<dyn ParRequestStore>) -> Self {
        let expires_in = if Self::valid_expires_in(expires_in) {
            expires_in
        } else {
            Self::DEFAULT_EXPIRES_IN
        };
        Self {
            request_store,
            #[cfg(test)]
            clients: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(test)]
            client_secret_credentials: Arc::new(RwLock::new(HashMap::new())),
            expires_in: AtomicU64::new(expires_in),
        }
    }

    pub(crate) fn authorization_code_commit_context(
        &self,
        request_uri: &str,
        expected_continuation: &str,
    ) -> Option<ParAuthorizationCodeCommit> {
        self.request_store
            .authorization_code_commit_context(request_uri, expected_continuation)
    }
}

fn invalid_request_uri_error() -> ParError {
    ParError {
        error: "invalid_request_uri".to_string(),
        error_description: Some("Request URI is invalid, expired, or already used".to_string()),
    }
}

/// Process a PAR request.
///
/// # Errors
///
/// Returns a `ParError` when client authentication, redirect URI validation,
/// scope validation, or PKCE validation fails.
pub fn process_par_request(store: &ParStore, request: ParRequest) -> Result<ParResponse, ParError> {
    store
        .validate_request(request)
        .and_then(|validated| store.store_request(validated))
}

/// Exchange `request_uri` for stored parameters.
///
/// # Errors
///
/// Returns a `ParError` when the supplied `request_uri` is unknown, expired,
/// or has already been consumed.
pub fn authorize_with_par(store: &ParStore, request_uri: &str) -> Result<ParRequest, ParError> {
    store
        .try_consume_request(request_uri)?
        .ok_or_else(invalid_request_uri_error)
}

/// Reserve `request_uri` for authorization parsing without consuming it.
///
/// # Errors
///
/// Returns a `ParError` when the supplied `request_uri` is unknown, expired, already reserved,
/// or bound to another client. Current client policy is validated by the authorization request
/// validator after the PAR request has been materialized.
pub fn reserve_authorize_with_par(
    store: &ParStore,
    request_uri: &str,
    expected_client_id: &str,
) -> Result<ReservedParRequest, ParError> {
    store.reserve_request_for_client(request_uri, expected_client_id)
}

/// Resume a reserved `request_uri` for a local-login continuation.
///
/// # Errors
///
/// Returns a `ParError` when the supplied `request_uri` is unknown, expired, already consumed,
/// bound to another client, or paired with the wrong continuation value.
pub fn resume_authorize_with_par(
    store: &ParStore,
    request_uri: &str,
    expected_client_id: &str,
    continuation: &str,
) -> Result<ParRequest, ParError> {
    store.resume_request_for_client(request_uri, expected_client_id, continuation)
}

#[cfg(test)]
mod tests;
