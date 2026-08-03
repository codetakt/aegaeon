use crate::config::{RuntimeRedisAtomicGroup, RuntimeStateNamespace};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc as StdArc;
#[cfg(test)]
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

const REPLAY_KEY_PREFIX: &str = "replay:v1";

/// Result of attempting to record a replay token.
#[derive(Debug, thiserror::Error)]
pub enum ReplayStoreError {
    #[error("replay detected")]
    Replay,
    #[error("replay store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("replay entry ttl cannot be represented")]
    RetentionOverflow,
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct RedisReplayCommitContext {
    pub(crate) url: StdArc<str>,
    pub(crate) key: String,
    pub(crate) ttl_ms: i64,
}

/// Entry describing a replay token to store.
pub struct ReplayEntry<'a> {
    pub namespace: &'a str,
    pub key_material: &'a [u8],
    pub ttl: Duration,
}

impl<'a> ReplayEntry<'a> {
    #[must_use]
    pub fn new(namespace: &'a str, key_material: &'a [u8], ttl: Duration) -> Self {
        Self {
            namespace,
            key_material,
            ttl,
        }
    }

    /// Encode the replay key with a canonical prefix.
    #[must_use]
    pub fn encoded_key(&self) -> String {
        format!("{REPLAY_KEY_PREFIX}:{}", self.encoded_digest())
    }

    #[must_use]
    fn encoded_digest(&self) -> String {
        let mut hasher = aegaeon_crypto::hash::Sha256Hasher::new();
        hasher.update(&replay_key_material(&[
            self.namespace.as_bytes(),
            self.key_material,
        ]));
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }
}

#[must_use]
pub(crate) fn replay_key_material(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().fold(0usize, |acc, part| {
        acc.saturating_add(std::mem::size_of::<u64>())
            .saturating_add(part.len())
    });
    let mut material = Vec::with_capacity(len);
    for part in parts {
        material.extend_from_slice(&(part.len() as u64).to_be_bytes());
        material.extend_from_slice(part);
    }
    material
}

#[cfg(test)]
fn lock_map<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, ReplayStoreError> {
    mutex.lock().map_err(|err| {
        ReplayStoreError::BackendUnavailable(format!("in-memory replay store lock poisoned: {err}"))
    })
}

/// Replay store interface.
pub trait ReplayStore: Send + Sync {
    /// # Errors
    ///
    /// Returns [`ReplayStoreError::Replay`] when the material was already
    /// recorded, or [`ReplayStoreError::BackendUnavailable`] when the backing
    /// store cannot confirm single-use semantics.
    fn check_and_store(&self, entry: ReplayEntry<'_>) -> Result<(), ReplayStoreError>;

    fn redis_commit_context(
        &self,
        _entry: ReplayEntry<'_>,
    ) -> Result<Option<RedisReplayCommitContext>, ReplayStoreError> {
        Ok(None)
    }
}

/// In-memory replay store used for tests.
#[derive(Default, Clone)]
#[cfg(test)]
pub struct InMemoryReplayStore {
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

#[cfg(test)]
impl InMemoryReplayStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[cfg(test)]
impl ReplayStore for InMemoryReplayStore {
    fn check_and_store(&self, entry: ReplayEntry<'_>) -> Result<(), ReplayStoreError> {
        let key = entry.encoded_key();
        let ttl = entry.ttl;
        let now = Instant::now();
        let expires_at = now
            .checked_add(ttl)
            .ok_or(ReplayStoreError::RetentionOverflow)?;

        let mut map = lock_map(&self.inner)?;
        map.retain(|_, expiry| *expiry > now);

        if map.contains_key(&key) {
            return Err(ReplayStoreError::Replay);
        }

        map.insert(key, expires_at);
        Ok(())
    }
}

pub(crate) fn ttl_millis_i64(ttl: Duration) -> Result<i64, ReplayStoreError> {
    ttl.as_millis()
        .try_into()
        .map(|ttl_ms: i64| ttl_ms.max(1))
        .map_err(|_| ReplayStoreError::RetentionOverflow)
}

/// Redis-backed replay store enforcing single-use semantics.
pub struct RedisReplayStore {
    client: redis::Client,
    url: StdArc<str>,
    prefix: StdArc<str>,
}

impl RedisReplayStore {
    /// # Errors
    ///
    /// Returns [`ReplayStoreError::BackendUnavailable`] when the Redis client
    /// cannot be constructed from the provided URL.
    pub fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
        surface: &str,
    ) -> Result<Self, ReplayStoreError> {
        Self::new_with_prefix(url, namespace.redis_prefix(surface, "replay:v1"))
    }

    /// # Errors
    ///
    /// Returns [`ReplayStoreError::BackendUnavailable`] when the Redis client
    /// cannot be constructed from the provided URL.
    pub fn new_in_atomic_group(
        url: &str,
        namespace: &RuntimeStateNamespace,
        group: RuntimeRedisAtomicGroup,
        surface: &str,
    ) -> Result<Self, ReplayStoreError> {
        Self::new_with_prefix(
            url,
            namespace.redis_atomic_group_prefix(group, surface, "replay:v1"),
        )
    }

    fn new_with_prefix(url: &str, prefix: String) -> Result<Self, ReplayStoreError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: StdArc::from(url.to_string().into_boxed_str()),
                prefix: StdArc::from(prefix.into_boxed_str()),
            })
            .map_err(|err| ReplayStoreError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub fn new_for_tests(url: &str) -> Result<Self, ReplayStoreError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: StdArc::from(url.to_string().into_boxed_str()),
                prefix: StdArc::from(REPLAY_KEY_PREFIX),
            })
            .map_err(|err| ReplayStoreError::BackendUnavailable(err.to_string()))
    }
}

impl ReplayStore for RedisReplayStore {
    fn check_and_store(&self, entry: ReplayEntry<'_>) -> Result<(), ReplayStoreError> {
        let key = format!("{}:{}", self.prefix, entry.encoded_digest());
        let ttl_ms = ttl_millis_i64(entry.ttl)?;

        let mut conn = self
            .client
            .get_connection()
            .map_err(|err| ReplayStoreError::BackendUnavailable(err.to_string()))?;

        let result: redis::Value = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query(&mut conn)
            .map_err(|err| ReplayStoreError::BackendUnavailable(err.to_string()))?;

        match result {
            redis::Value::Okay => Ok(()),
            redis::Value::Nil => Err(ReplayStoreError::Replay),
            other => Err(ReplayStoreError::BackendUnavailable(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    fn redis_commit_context(
        &self,
        entry: ReplayEntry<'_>,
    ) -> Result<Option<RedisReplayCommitContext>, ReplayStoreError> {
        Ok(Some(RedisReplayCommitContext {
            url: self.url.clone(),
            key: format!("{}:{}", self.prefix, entry.encoded_digest()),
            ttl_ms: ttl_millis_i64(entry.ttl)?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn in_memory_replay_store_rejects_unrepresentable_ttl() {
        let store = InMemoryReplayStore::new();
        let entry = ReplayEntry::new("test", b"entry", Duration::MAX);

        let result = store.check_and_store(entry);

        assert!(matches!(result, Err(ReplayStoreError::RetentionOverflow)));
    }

    #[test]
    fn in_memory_replay_store_fails_closed_after_lock_poisoning() {
        let store = InMemoryReplayStore::new();
        let inner = Arc::clone(&store.inner);
        let _ = thread::spawn(move || {
            let Ok(_guard) = inner.lock() else {
                return;
            };
            std::panic::panic_any("poison replay store");
        })
        .join();

        let result =
            store.check_and_store(ReplayEntry::new("test", b"entry", Duration::from_secs(60)));

        assert!(matches!(
            result,
            Err(ReplayStoreError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn redis_ttl_conversion_rejects_unrepresentable_ttl() {
        assert!(matches!(
            ttl_millis_i64(Duration::MAX),
            Err(ReplayStoreError::RetentionOverflow)
        ));
    }

    #[test]
    fn redis_ttl_conversion_clamps_zero_to_one_millisecond() {
        assert!(matches!(ttl_millis_i64(Duration::ZERO), Ok(1)));
    }

    #[test]
    fn replay_key_material_is_length_delimited() {
        assert_ne!(
            replay_key_material(&[b"a\0b", b"c"]),
            replay_key_material(&[b"a", b"b\0c"])
        );
    }

    #[test]
    fn encoded_key_uses_generic_prefix_and_hashes_namespace_boundary() {
        let first = ReplayEntry::new("ab", b"c", Duration::from_secs(60)).encoded_key();
        let second = ReplayEntry::new("a", b"bc", Duration::from_secs(60)).encoded_key();

        assert!(first.starts_with("replay:v1:"));
        assert_ne!(first, second);
        assert!(!first.contains("ab"));
    }
}
