use super::auth_store::{
    RedisUpstreamAuthStoreBackend, UpstreamAuthStorageError, UPSTREAM_AUTH_REDIS_URL_ENV,
};
use super::UpstreamAuthRequest;
#[cfg(test)]
use crate::config::DEFAULT_UPSTREAM_AUTH_TTL_SECS;
use crate::config::{
    require_shared_runtime_store_url, valid_upstream_auth_ttl_secs, ConfigError,
    RuntimeStateNamespace,
};
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

#[derive(Clone)]
pub struct UpstreamAuthStore {
    backend: UpstreamAuthStoreBackend,
    ttl: Duration,
}

#[derive(Clone)]
enum UpstreamAuthStoreBackend {
    #[cfg(test)]
    InMemory(Arc<RwLock<HashMap<String, UpstreamAuthRequest>>>),
    Redis(RedisUpstreamAuthStoreBackend),
}

fn log_upstream_auth_storage_error(error: &UpstreamAuthStorageError, operation: &str) {
    tracing::error!(error = %error, operation, "upstream auth store operation failed");
}

impl UpstreamAuthStore {
    /// Create a process-local upstream auth-state store for tests.
    ///
    /// Production code should use [`Self::try_new_from_shared_store_env_with_ttl_secs`] so shared
    /// runtime state is required and the TTL comes from the management configuration snapshot.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::with_ttl_secs(DEFAULT_UPSTREAM_AUTH_TTL_SECS)
    }

    pub fn try_new_from_shared_store_env_with_ttl_secs(
        ttl_secs: u64,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        if !valid_upstream_auth_ttl_secs(ttl_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "upstream_auth_ttl_seconds".to_string(),
                value: ttl_secs.to_string(),
                expectation: "a value in 1..=3600 seconds".to_string(),
            });
        }
        let url = require_shared_runtime_store_url(
            "upstream auth state store",
            UPSTREAM_AUTH_REDIS_URL_ENV,
        )?;
        let backend = RedisUpstreamAuthStoreBackend::new(url.as_str(), runtime_state_namespace)
            .map_err(|err| ConfigError::InvalidValue {
                key: url.env_key().to_string(),
                value: "[redacted]".to_string(),
                reason: err.to_string(),
            })?;
        tracing::info!("upstream auth store backend: redis");
        Ok(Self {
            backend: UpstreamAuthStoreBackend::Redis(backend),
            ttl: Duration::from_secs(ttl_secs),
        })
    }

    #[cfg(test)]
    fn with_ttl_secs(ttl_secs: u64) -> Self {
        Self {
            backend: UpstreamAuthStoreBackend::InMemory(Arc::new(RwLock::new(HashMap::new()))),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    #[cfg(test)]
    pub(super) fn redis_for_test(url: &str, key: &str, ttl_secs: u64) -> Result<Self, String> {
        Ok(Self {
            backend: UpstreamAuthStoreBackend::Redis(
                RedisUpstreamAuthStoreBackend::new_with_key(url, Arc::<str>::from(key.to_string()))
                    .map_err(|err| format!("redis upstream auth store: {err}"))?,
            ),
            ttl: Duration::from_secs(ttl_secs),
        })
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn try_insert(&self, request: UpstreamAuthRequest) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            UpstreamAuthStoreBackend::InMemory(entries) => {
                let mut entries = entries
                    .write()
                    .map_err(|err| format!("upstream auth store lock poisoned: {err}"))?;
                if entries.get(&request.state).is_some_and(|existing| {
                    upstream_auth_request_is_fresh_at(existing, SystemTime::now())
                }) {
                    return Err("upstream auth state already exists".to_string());
                }
                entries.insert(request.state.clone(), request);
                Ok(())
            }
            UpstreamAuthStoreBackend::Redis(backend) => backend.insert(&request).map_err(|err| {
                let message = err.to_string();
                log_upstream_auth_storage_error(&err, "insert");
                message
            }),
        }
    }

    pub async fn try_insert_async(&self, request: UpstreamAuthRequest) -> Result<(), String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_insert(request))
            .await
            .map_err(|err| format!("upstream auth store worker failed: {err}"))?
    }

    pub fn try_consume(&self, state: &str) -> Result<Option<UpstreamAuthRequest>, String> {
        match &self.backend {
            #[cfg(test)]
            UpstreamAuthStoreBackend::InMemory(entries) => {
                let mut entries = entries
                    .write()
                    .map_err(|err| format!("upstream auth store lock poisoned: {err}"))?;
                let Some(request) = entries.remove(state) else {
                    return Ok(None);
                };
                if !upstream_auth_request_is_fresh_at(&request, SystemTime::now()) {
                    return Ok(None);
                }
                Ok(Some(request))
            }
            UpstreamAuthStoreBackend::Redis(backend) => backend.consume(state).map_err(|err| {
                let message = err.to_string();
                log_upstream_auth_storage_error(&err, "consume");
                message
            }),
        }
    }

    pub async fn try_consume_async(
        &self,
        state: String,
    ) -> Result<Option<UpstreamAuthRequest>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_consume(&state))
            .await
            .map_err(|err| format!("upstream auth store worker failed: {err}"))?
    }

    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            UpstreamAuthStoreBackend::InMemory(entries) => {
                let mut entries = entries
                    .write()
                    .map_err(|err| format!("upstream auth store lock poisoned: {err}"))?;
                let now = SystemTime::now();
                entries.retain(|_, request| upstream_auth_request_is_fresh_at(request, now));
                Ok(())
            }
            UpstreamAuthStoreBackend::Redis(_) => Ok(()),
        }
    }

    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test upstream auth cleanup should succeed");
    }
}

pub(super) fn upstream_auth_request_is_fresh_at(
    request: &UpstreamAuthRequest,
    now: SystemTime,
) -> bool {
    now < request.expires_at
}
