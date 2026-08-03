use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use thiserror::Error;

use super::jwks_types::CacheEntry;
use super::{sha256_hex, ClientRegistryInitError, JwksRuntimePolicy, JWKS_REDIS_URL_ENV};
use crate::config::{require_shared_runtime_store_url, RuntimeStateNamespace};

mod redis_circuit;
mod redis_kid;

pub(super) enum JwksSharedRuntimeState {
    #[cfg(any(test, kani))]
    InMemory,
    Redis(RedisJwksRuntimeState),
}

pub(super) struct RedisJwksRuntimeState {
    client: redis::Client,
    prefix: Arc<str>,
}

#[derive(Debug, Error)]
pub(super) enum JwksSharedStateError {
    #[error("JWKS shared runtime state backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("JWKS shared runtime state TTL cannot be represented")]
    RetentionOverflow,
}

impl RedisJwksRuntimeState {
    pub(super) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, JwksSharedStateError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                prefix: Arc::from(
                    namespace
                        .redis_prefix("jwks-runtime", "v1")
                        .into_boxed_str(),
                ),
            })
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(super) fn new_for_tests(url: &str) -> Result<Self, JwksSharedStateError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                prefix: Arc::from("jwks-runtime:v1"),
            })
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, JwksSharedStateError> {
        self.client
            .get_connection()
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))
    }
}

#[derive(Clone)]
pub(super) struct JwksRuntimeState {
    pub(super) inner: Arc<JwksRuntimeStateInner>,
}

pub(super) struct JwksRuntimeStateInner {
    pub(super) cache: Mutex<HashMap<String, CacheEntry>>,
    pub(super) last_gc: Mutex<Option<std::time::Instant>>,
    pub(super) coordination: JwksCoordinationState,
    pub(super) shared_state: JwksSharedRuntimeState,
}

pub(super) struct JwksCoordinationState {
    pub(super) fetch_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    pub(super) circuits: Mutex<HashMap<String, CircuitState>>,
    pub(super) background_refreshes: Mutex<HashSet<String>>,
}

#[derive(Debug, Error)]
pub(super) enum JwksCoordinationError {
    #[error("JWKS coordination lock poisoned: {0}")]
    LockPoisoned(&'static str),
}

impl JwksCoordinationState {
    fn new() -> Self {
        Self {
            fetch_locks: Mutex::new(HashMap::new()),
            circuits: Mutex::new(HashMap::new()),
            background_refreshes: Mutex::new(HashSet::new()),
        }
    }

    pub(super) fn fetch_lock(
        &self,
        max_entries: usize,
        uri: &str,
    ) -> Result<Option<Arc<Mutex<()>>>, JwksCoordinationError> {
        let max_entries = max_entries.max(1);
        let mut locks = self
            .fetch_locks
            .lock()
            .map_err(|_| JwksCoordinationError::LockPoisoned("fetch_locks"))?;

        if !locks.contains_key(uri) {
            prune_idle_fetch_locks(&mut locks, max_entries);
        }
        if !locks.contains_key(uri) && locks.len() >= max_entries {
            return Ok(None);
        }

        Ok(Some(
            locks
                .entry(uri.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone(),
        ))
    }

    pub(super) fn mark_background_refresh_started(
        &self,
        max_entries: usize,
        uri: &str,
    ) -> Result<bool, JwksCoordinationError> {
        let max_entries = max_entries.max(1);
        let mut refreshes = self
            .background_refreshes
            .lock()
            .map_err(|_| JwksCoordinationError::LockPoisoned("background_refreshes"))?;

        if refreshes.contains(uri) {
            return Ok(false);
        }
        if refreshes.len() >= max_entries {
            return Ok(false);
        }

        Ok(refreshes.insert(uri.to_string()))
    }

    pub(super) fn mark_background_refresh_finished(
        &self,
        uri: &str,
    ) -> Result<(), JwksCoordinationError> {
        let mut refreshes = self
            .background_refreshes
            .lock()
            .map_err(|_| JwksCoordinationError::LockPoisoned("background_refreshes"))?;
        refreshes.remove(uri);
        Ok(())
    }

    pub(super) fn prune_idle_fetch_locks(
        &self,
        max_entries: usize,
    ) -> Result<(), JwksCoordinationError> {
        let mut locks = self
            .fetch_locks
            .lock()
            .map_err(|_| JwksCoordinationError::LockPoisoned("fetch_locks"))?;
        prune_idle_fetch_locks(&mut locks, max_entries.max(1));
        Ok(())
    }
}

fn prune_idle_fetch_locks(locks: &mut HashMap<String, Arc<Mutex<()>>>, max_entries: usize) {
    if locks.len() < max_entries {
        return;
    }

    let mut idle_uris = locks
        .iter()
        .filter(|(_, lock)| Arc::strong_count(lock) == 1)
        .map(|(uri, _)| uri.clone())
        .collect::<Vec<_>>();
    idle_uris.sort();

    for uri in idle_uris {
        if locks.len() < max_entries {
            break;
        }
        locks.remove(&uri);
    }
}

#[cfg(any(test, kani))]
impl Default for JwksRuntimeState {
    fn default() -> Self {
        Self::with_shared_state(JwksSharedRuntimeState::InMemory)
    }
}

impl JwksRuntimeState {
    pub(super) fn with_shared_state(shared_state: JwksSharedRuntimeState) -> Self {
        Self {
            inner: Arc::new(JwksRuntimeStateInner {
                cache: Mutex::new(HashMap::new()),
                last_gc: Mutex::new(None),
                coordination: JwksCoordinationState::new(),
                shared_state,
            }),
        }
    }

    pub(super) fn redis_shared_state(&self) -> Option<&RedisJwksRuntimeState> {
        #[cfg(any(test, kani))]
        {
            match &self.inner.shared_state {
                JwksSharedRuntimeState::InMemory => None,
                JwksSharedRuntimeState::Redis(redis_state) => Some(redis_state),
            }
        }
        #[cfg(not(any(test, kani)))]
        {
            let JwksSharedRuntimeState::Redis(redis_state) = &self.inner.shared_state;
            Some(redis_state)
        }
    }

    pub(super) fn try_from_env(
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ClientRegistryInitError> {
        let url = require_shared_runtime_store_url("JWKS runtime state", JWKS_REDIS_URL_ENV)?;
        let shared_state = JwksSharedRuntimeState::Redis(
            RedisJwksRuntimeState::new(url.as_str(), runtime_state_namespace)
                .map_err(|err| ClientRegistryInitError::JwksSharedState(err.to_string()))?,
        );
        Ok(Self::with_shared_state(shared_state))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CircuitPhase {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitPhase {
    const fn as_redis_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }

    fn from_redis_str(value: &str) -> Self {
        match value {
            "open" => Self::Open,
            "half_open" => Self::HalfOpen,
            _ => Self::Closed,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct CircuitState {
    pub(super) phase: CircuitPhase,
    pub(super) consecutive_failures: u32,
    pub(super) opened_at: Option<std::time::Instant>,
    pub(super) probe_in_flight: bool,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self {
            phase: CircuitPhase::Closed,
            consecutive_failures: 0,
            opened_at: None,
            probe_in_flight: false,
        }
    }
}

impl RedisJwksRuntimeState {
    pub(super) fn key(&self, kind: &str, uri: &str) -> String {
        format!("{}:{kind}:{}", self.prefix, sha256_hex(uri.as_bytes()))
    }

    fn shared_ttl_secs(policy: &JwksRuntimePolicy) -> u64 {
        [
            policy.cache_ttl_secs,
            policy.shared_state_max_age_secs,
            policy.circuit_reset_secs.saturating_mul(4),
            60,
        ]
        .into_iter()
        .max()
        .unwrap_or(60)
    }

    fn ttl_i64(policy: &JwksRuntimePolicy) -> Result<i64, JwksSharedStateError> {
        Self::shared_ttl_secs(policy)
            .try_into()
            .map(|ttl: i64| ttl.max(1))
            .map_err(|_| JwksSharedStateError::RetentionOverflow)
    }

    fn now_epoch_millis_i64() -> Result<i64, JwksSharedStateError> {
        let millis = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))?
            .as_millis();
        millis
            .try_into()
            .map_err(|_| JwksSharedStateError::RetentionOverflow)
    }
}
