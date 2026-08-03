use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::sync::Arc;
#[cfg(test)]
use std::sync::{RwLock, RwLockWriteGuard};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

use super::super::replay_store::{replay_key_material, ttl_millis_i64, ReplayStoreError};
use super::DpopError;

#[cfg(test)]
struct NonceEntry {
    value: String,
    previous: Option<String>,
    issued_at: Instant,
    /// Timestamp when the previous nonce was installed (grace window start).
    rotated_at: Option<Instant>,
}

enum DpopNonceBackend {
    #[cfg(test)]
    InMemory {
        inner: RwLock<NonceEntry>,
    },
    Redis(RedisDpopNonceStore),
}

struct RedisDpopNonceStore {
    client: redis::Client,
    namespace: Arc<str>,
}

/// DPoP nonce store with time-bounded rotation (RFC 9449 Section 5).
///
/// The Redis backend issues independently retained nonces so multiple server
/// instances can accept the same nonce namespace without sticky sessions.
pub struct DpopNonceStore {
    backend: DpopNonceBackend,
    ttl: Duration,
}

#[cfg(test)]
fn write_lock<T>(lock: &RwLock<T>) -> Result<RwLockWriteGuard<'_, T>, DpopError> {
    match lock.write() {
        Ok(guard) => Ok(guard),
        Err(err) => {
            tracing::error!(error = %err, "DPoP nonce store lock poisoned");
            Err(DpopError::BackendUnavailable(
                "DPoP nonce store lock poisoned".to_string(),
            ))
        }
    }
}

impl DpopNonceStore {
    /// Create a process-local nonce store with the given TTL per nonce.
    ///
    /// Production code must use [`Self::redis`] so DPoP nonce state is shared
    /// across server instances.
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local(ttl: Duration) -> Self {
        let value = Self::generate_nonce();
        Self {
            backend: DpopNonceBackend::InMemory {
                inner: RwLock::new(NonceEntry {
                    value,
                    previous: None,
                    issued_at: Instant::now(),
                    rotated_at: None,
                }),
            },
            ttl,
        }
    }

    /// Create a Redis-backed nonce store for shared multi-instance deployments.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayStoreError::BackendUnavailable`] if the Redis URL cannot
    /// be parsed by the Redis client.
    pub fn redis(
        url: &str,
        namespace: impl Into<Arc<str>>,
        ttl: Duration,
    ) -> Result<Self, ReplayStoreError> {
        Ok(Self {
            backend: DpopNonceBackend::Redis(RedisDpopNonceStore::new(url, namespace.into())?),
            ttl,
        })
    }

    fn generate_nonce() -> String {
        let buf = aegaeon_crypto::rand::ring_random_nonce_32();
        URL_SAFE_NO_PAD.encode(buf)
    }

    #[cfg(test)]
    fn maybe_rotate(entry: &mut NonceEntry, ttl: Duration) {
        if entry.issued_at.elapsed() >= ttl {
            let fresh = Self::generate_nonce();
            entry.previous = Some(std::mem::replace(&mut entry.value, fresh));
            entry.rotated_at = Some(Instant::now());
            entry.issued_at = Instant::now();
        }
    }

    /// Return the current nonce value, rotating if the TTL has elapsed.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::BackendUnavailable`] when the backing store cannot
    /// retain the nonce for later validation.
    pub fn get_current_nonce(&self) -> Result<String, DpopError> {
        self.try_get_current_nonce()
    }

    /// Return a nonce suitable for a `DPoP-Nonce` challenge.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::BackendUnavailable`] when the backing store cannot
    /// retain the nonce for later validation.
    pub fn try_get_current_nonce(&self) -> Result<String, DpopError> {
        match &self.backend {
            #[cfg(test)]
            DpopNonceBackend::InMemory { inner } => {
                let mut entry = write_lock(inner)?;
                Self::maybe_rotate(&mut entry, self.ttl);
                Ok(entry.value.clone())
            }
            DpopNonceBackend::Redis(store) => store.issue_nonce(self.ttl),
        }
    }

    /// Check if `nonce` matches the current or previous (grace-period) value.
    ///
    /// The previous nonce is only accepted within a bounded grace window
    /// (equal to `ttl`) after the rotation event. This prevents indefinite
    /// acceptance of stale nonces after long idle periods.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::BackendUnavailable`] when the backing store cannot
    /// confirm nonce validity.
    pub fn validate_nonce(&self, nonce: &str) -> Result<bool, DpopError> {
        self.try_validate_nonce(nonce)
    }

    /// Check if `nonce` is currently accepted by the backend.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::BackendUnavailable`] when the backing store cannot
    /// confirm nonce validity.
    pub fn try_validate_nonce(&self, nonce: &str) -> Result<bool, DpopError> {
        match &self.backend {
            #[cfg(test)]
            DpopNonceBackend::InMemory { inner } => {
                let mut entry = write_lock(inner)?;
                Self::maybe_rotate(&mut entry, self.ttl);
                if entry.value == nonce {
                    return Ok(true);
                }
                // Accept previous nonce only within the grace window after rotation.
                Ok(match (&entry.previous, entry.rotated_at) {
                    (Some(prev), Some(rotated)) if prev == nonce => rotated.elapsed() < self.ttl,
                    _ => false,
                })
            }
            DpopNonceBackend::Redis(store) => store.validate_nonce(nonce),
        }
    }

    #[cfg(test)]
    pub(in crate::middleware::dpop) fn force_rotate_for_test(
        &self,
    ) -> Result<(String, String), DpopError> {
        let DpopNonceBackend::InMemory { inner } = &self.backend else {
            return Err(DpopError::BackendUnavailable(
                "test nonce rotation helper requires in-memory backend".to_string(),
            ));
        };
        let mut entry = write_lock(inner)?;
        let previous = entry.value.clone();
        let current = Self::generate_nonce();
        let now = Instant::now();
        entry.previous = Some(previous.clone());
        entry.value.clone_from(&current);
        entry.rotated_at = Some(now);
        entry.issued_at = now;
        Ok((previous, current))
    }

    #[cfg(test)]
    pub(in crate::middleware::dpop) fn backdate_rotation_for_test(
        &self,
        age: Duration,
    ) -> Result<(), DpopError> {
        let DpopNonceBackend::InMemory { inner } = &self.backend else {
            return Err(DpopError::BackendUnavailable(
                "test nonce rotation helper requires in-memory backend".to_string(),
            ));
        };
        let mut entry = write_lock(inner)?;
        entry.rotated_at = Some(Instant::now().checked_sub(age).unwrap_or_else(Instant::now));
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::middleware::dpop) fn poison_for_test(&self) -> Result<(), DpopError> {
        let DpopNonceBackend::InMemory { inner } = &self.backend else {
            return Err(DpopError::BackendUnavailable(
                "test nonce poison helper requires in-memory backend".to_string(),
            ));
        };

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(_guard) = inner.write() else {
                return;
            };
            std::panic::panic_any("poison nonce store");
        }));
        Ok(())
    }
}

impl RedisDpopNonceStore {
    fn new(url: &str, namespace: Arc<str>) -> Result<Self, ReplayStoreError> {
        redis::Client::open(url)
            .map(|client| Self { client, namespace })
            .map_err(|err| ReplayStoreError::BackendUnavailable(err.to_string()))
    }

    fn nonce_key(&self, nonce: &str) -> String {
        let material = replay_key_material(&[self.namespace.as_bytes(), nonce.as_bytes()]);
        let digest = aegaeon_crypto::hash::sha256_digest(&material);
        let encoded = URL_SAFE_NO_PAD.encode(digest);
        format!("dpop:nonce:v1:{encoded}")
    }

    fn connection(&self) -> Result<redis::Connection, DpopError> {
        self.client
            .get_connection()
            .map_err(|err| DpopError::BackendUnavailable(err.to_string()))
    }

    fn issue_nonce(&self, ttl: Duration) -> Result<String, DpopError> {
        let nonce = DpopNonceStore::generate_nonce();
        let key = self.nonce_key(&nonce);
        let ttl_ms =
            ttl_millis_i64(ttl).map_err(|err| DpopError::BackendUnavailable(err.to_string()))?;
        let mut conn = self.connection()?;
        redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("PX")
            .arg(ttl_ms)
            .query::<()>(&mut conn)
            .map_err(|err| DpopError::BackendUnavailable(err.to_string()))?;
        Ok(nonce)
    }

    fn validate_nonce(&self, nonce: &str) -> Result<bool, DpopError> {
        let key = self.nonce_key(nonce);
        let mut conn = self.connection()?;
        let count = redis::cmd("EXISTS")
            .arg(&key)
            .query::<i64>(&mut conn)
            .map_err(|err| DpopError::BackendUnavailable(err.to_string()))?;
        Ok(count > 0)
    }
}
