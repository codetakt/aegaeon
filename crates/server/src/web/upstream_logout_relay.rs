#[cfg(test)]
use crate::organizations::request_work::async_store::blocking;
#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use crate::config::require_shared_runtime_store_url;
#[cfg(test)]
use crate::config::DEFAULT_UPSTREAM_LOGOUT_RELAY_TTL_SECS;
use crate::config::{valid_upstream_logout_relay_ttl_secs, ConfigError, RuntimeStateNamespace};
#[cfg(test)]
use entry::RedisUpstreamLogoutRelayEntry;
mod postgres;
use postgres::PostgresLogoutRelayStore;
#[cfg(test)]
use process_local::ProcessLocalLogoutRelayBackend;

#[cfg(test)]
#[path = "upstream_logout_relay/entry.rs"]
mod entry;
#[cfg(test)]
#[path = "upstream_logout_relay/process_local.rs"]
mod process_local;
#[cfg(test)]
#[path = "upstream_logout_relay/scripts.rs"]
mod scripts;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamLogoutRelayState {
    pub(super) incident_id: Option<uuid::Uuid>,
    pub(super) downstream_redirect_uri: String,
    pub(super) downstream_state: Option<String>,
}

#[cfg(test)]
const UPSTREAM_LOGOUT_RELAY_REDIS_URL_ENV: &str = "AEGAEON_TEST_UPSTREAM_LOGOUT_RELAY_REDIS_URL";

#[derive(Clone)]
pub struct UpstreamLogoutRelayStore {
    backend: UpstreamLogoutRelayBackend,
    ttl: Duration,
}

#[derive(Clone)]
enum UpstreamLogoutRelayBackend {
    #[cfg(test)]
    InMemory(ProcessLocalLogoutRelayBackend),
    #[cfg(test)]
    Redis(RedisUpstreamLogoutRelayBackend),
    Postgres(PostgresLogoutRelayStore),
}

#[cfg(test)]
#[derive(Clone)]
struct RedisUpstreamLogoutRelayBackend {
    client: redis::Client,
    key: Arc<str>,
}

#[cfg(test)]
#[derive(Debug, thiserror::Error)]
enum UpstreamLogoutRelayStorageError {
    #[error("upstream logout relay store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("upstream logout relay state already exists")]
    Collision,
    #[error("upstream logout relay store payload cannot be encoded: {0}")]
    Codec(String),
}

#[cfg(test)]
fn log_storage_error(error: &UpstreamLogoutRelayStorageError, operation: &str) {
    tracing::error!(error = %error, operation, "upstream logout relay store operation failed");
}

#[cfg(test)]
fn storage_error_message(
    error: &UpstreamLogoutRelayStorageError,
    operation: &'static str,
) -> String {
    let message = error.to_string();
    log_storage_error(error, operation);
    message
}

#[cfg(test)]
fn try_now_epoch_secs(operation: &'static str) -> Result<u64, String> {
    crate::util::now_unix_epoch_secs().map_err(|err| {
        let error = UpstreamLogoutRelayStorageError::BackendUnavailable(format!(
            "system clock is before Unix epoch: {err}"
        ));
        storage_error_message(&error, operation)
    })
}

#[cfg(test)]
impl RedisUpstreamLogoutRelayBackend {
    fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, UpstreamLogoutRelayStorageError> {
        Self::new_with_key(url, namespace.redis_prefix("upstream-logout-relay", "v1"))
    }

    fn new_with_key(
        url: &str,
        key: impl Into<Arc<str>>,
    ) -> Result<Self, UpstreamLogoutRelayStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                key: key.into(),
            })
            .map_err(|err| UpstreamLogoutRelayStorageError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<crate::redis_io::Connection, UpstreamLogoutRelayStorageError> {
        crate::redis_io::connect(&self.client)
            .map_err(|err| UpstreamLogoutRelayStorageError::BackendUnavailable(err.to_string()))
    }

    fn relay_key(&self, relay_token: &str) -> String {
        format!(
            "{}:{}",
            self.key,
            aegaeon_crypto::hash::sha256_hex(relay_token.as_bytes())
        )
    }

    fn insert(
        &self,
        relay_token: &str,
        value: &UpstreamLogoutRelayState,
        expires_at_epoch_secs: u64,
        ttl: Duration,
    ) -> Result<(), UpstreamLogoutRelayStorageError> {
        let entry = RedisUpstreamLogoutRelayEntry::from_state(value, expires_at_epoch_secs);
        let payload = serde_json::to_string(&entry)
            .map_err(|err| UpstreamLogoutRelayStorageError::Codec(err.to_string()))?;
        let ttl_millis = u64::try_from(ttl.as_millis().max(1)).map_err(|_| {
            UpstreamLogoutRelayStorageError::Codec("logout relay ttl overflow".into())
        })?;
        let key = self.relay_key(relay_token);
        let mut conn = self.connection()?;
        match redis::cmd("SET")
            .arg(key)
            .arg(payload)
            .arg("NX")
            .arg("PX")
            .arg(ttl_millis)
            .query::<redis::Value>(&mut conn)
            .map_err(|err| UpstreamLogoutRelayStorageError::BackendUnavailable(err.to_string()))?
        {
            redis::Value::Okay => Ok(()),
            redis::Value::Nil => Err(UpstreamLogoutRelayStorageError::Collision),
            other => Err(UpstreamLogoutRelayStorageError::BackendUnavailable(
                format!("unexpected Redis SET response: {other:?}"),
            )),
        }
    }

    fn take(
        &self,
        relay_token: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<UpstreamLogoutRelayState>, UpstreamLogoutRelayStorageError> {
        let key = self.relay_key(relay_token);
        let mut conn = self.connection()?;
        let payload = redis::Script::new(scripts::TAKE_RELAY)
            .key(key)
            .invoke::<Option<String>>(&mut conn)
            .map_err(|err| UpstreamLogoutRelayStorageError::BackendUnavailable(err.to_string()))?;
        payload
            .map(|payload| {
                serde_json::from_str::<RedisUpstreamLogoutRelayEntry>(&payload)
                    .map_err(|err| UpstreamLogoutRelayStorageError::Codec(err.to_string()))
                    .map(|entry| entry.into_state(now_epoch_secs))
            })
            .transpose()
            .map(Option::flatten)
    }
}

impl UpstreamLogoutRelayStore {
    #[cfg(test)]
    pub fn try_new_from_shared_store_env_with_ttl_secs(
        ttl_secs: u64,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        if !valid_upstream_logout_relay_ttl_secs(ttl_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "upstream_logout_relay_ttl_seconds".to_string(),
                value: ttl_secs.to_string(),
                expectation: "a value in 1..=86400 seconds".to_string(),
            });
        }
        let url = require_shared_runtime_store_url(
            "upstream logout relay store",
            UPSTREAM_LOGOUT_RELAY_REDIS_URL_ENV,
        )?;
        let backend = RedisUpstreamLogoutRelayBackend::new(url.as_str(), runtime_state_namespace)
            .map_err(|err| ConfigError::InvalidValue {
            key: url.env_key().to_string(),
            value: "[redacted]".to_string(),
            reason: err.to_string(),
        })?;
        tracing::info!("upstream logout relay store backend: redis");
        Ok(Self {
            backend: UpstreamLogoutRelayBackend::Redis(backend),
            ttl: Duration::from_secs(ttl_secs),
        })
    }

    pub fn from_postgres(
        pool: sqlx::PgPool,
        namespace: &RuntimeStateNamespace,
        ttl_secs: u64,
    ) -> Result<Self, ConfigError> {
        if !valid_upstream_logout_relay_ttl_secs(ttl_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "upstream_logout_relay_ttl_seconds".into(),
                value: ttl_secs.to_string(),
                expectation: "a value in 1..=86400 seconds".into(),
            });
        }
        Ok(Self {
            backend: UpstreamLogoutRelayBackend::Postgres(PostgresLogoutRelayStore::new(
                pool,
                namespace.flow_namespace("upstream", "logout-relay"),
            )),
            ttl: Duration::from_secs(ttl_secs),
        })
    }

    /// Create a process-local upstream logout relay store for tests.
    ///
    /// Production code should use [`Self::from_postgres`] so shared
    /// runtime state is required and the TTL comes from the management configuration snapshot.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local_with_ttl_secs_for_tests(DEFAULT_UPSTREAM_LOGOUT_RELAY_TTL_SECS)
    }

    /// Create a process-local upstream logout relay store with an explicit TTL for tests.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_with_ttl_secs_for_tests(ttl_secs: u64) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            backend: UpstreamLogoutRelayBackend::InMemory(ProcessLocalLogoutRelayBackend::default()),
        }
    }

    #[cfg(test)]
    pub(super) fn redis_for_test(url: &str, key: &str, ttl: Duration) -> Result<Self, String> {
        Ok(Self {
            backend: UpstreamLogoutRelayBackend::Redis(
                RedisUpstreamLogoutRelayBackend::new_with_key(
                    url,
                    Arc::<str>::from(key.to_string()),
                )
                .map_err(|err| format!("redis upstream logout relay store: {err}"))?,
            ),
            ttl,
        })
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    #[cfg(test)]
    pub fn try_insert(
        &self,
        relay_token: &str,
        value: UpstreamLogoutRelayState,
    ) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            UpstreamLogoutRelayBackend::InMemory(backend) => backend
                .insert(relay_token, value, self.ttl)
                .map_err(|err| storage_error_message(&err, "insert")),
            UpstreamLogoutRelayBackend::Postgres(_) => {
                Err("asynchronous relay admission required".into())
            }
            UpstreamLogoutRelayBackend::Redis(backend) => {
                let expires_at_epoch_secs = try_now_epoch_secs("insert")?
                    .checked_add(self.ttl.as_secs())
                    .ok_or_else(|| {
                        "logout relay TTL expiration cannot be represented".to_string()
                    })?;
                backend
                    .insert(relay_token, &value, expires_at_epoch_secs, self.ttl)
                    .map_err(|err| storage_error_message(&err, "insert"))
            }
        }
    }

    pub async fn try_insert_async(
        &self,
        relay_token: String,
        value: UpstreamLogoutRelayState,
    ) -> Result<(), String> {
        match &self.backend {
            UpstreamLogoutRelayBackend::Postgres(store) => {
                store.insert(&relay_token, &value, self.ttl).await
            }
            #[cfg(test)]
            _ => {
                let store = self.clone();
                blocking(move || store.try_insert(&relay_token, value))
                    .await
                    .map_err(|err| format!("upstream logout relay worker failed: {err}"))?
            }
        }
    }

    #[cfg(test)]
    pub fn try_take(&self, relay_token: &str) -> Result<Option<UpstreamLogoutRelayState>, String> {
        match &self.backend {
            #[cfg(test)]
            UpstreamLogoutRelayBackend::InMemory(backend) => backend
                .take(relay_token)
                .map_err(|err| storage_error_message(&err, "take")),
            UpstreamLogoutRelayBackend::Postgres(_) => {
                Err("asynchronous relay admission required".into())
            }
            UpstreamLogoutRelayBackend::Redis(backend) => {
                let now = try_now_epoch_secs("take")?;
                backend
                    .take(relay_token, now)
                    .map_err(|err| storage_error_message(&err, "take"))
            }
        }
    }

    pub async fn try_take_async(
        &self,
        relay_token: String,
    ) -> Result<Option<UpstreamLogoutRelayState>, String> {
        match &self.backend {
            UpstreamLogoutRelayBackend::Postgres(store) => store.take(&relay_token).await,
            #[cfg(test)]
            _ => {
                let store = self.clone();
                blocking(move || store.try_take(&relay_token))
                    .await
                    .map_err(|err| format!("upstream logout relay worker failed: {err}"))?
            }
        }
    }

    pub async fn cleanup_async(&self) -> Result<(), String> {
        match &self.backend {
            UpstreamLogoutRelayBackend::Postgres(store) => store.cleanup().await,
            #[cfg(test)]
            _ => {
                let store = self.clone();
                blocking(move || store.try_cleanup_expired())
                    .await
                    .map_err(|err| format!("upstream logout relay worker failed: {err}"))?
            }
        }
    }

    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test upstream logout relay cleanup should succeed");
    }

    #[cfg(test)]
    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            UpstreamLogoutRelayBackend::InMemory(backend) => backend
                .cleanup_expired()
                .map_err(|err| storage_error_message(&err, "cleanup_expired")),
            UpstreamLogoutRelayBackend::Redis(_) => Ok(()),
            UpstreamLogoutRelayBackend::Postgres(_) => {
                Err("asynchronous relay admission required".into())
            }
        }
    }
}

#[cfg(test)]
#[path = "upstream_logout_relay/organization_epoch.rs"]
mod organization_epoch;
