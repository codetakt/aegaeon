use super::{
    valid_upstream_metadata_cache_max_entries, valid_upstream_metadata_cache_ttl_secs,
    DEFAULT_UPSTREAM_METADATA_CACHE_MAX_ENTRIES, DEFAULT_UPSTREAM_METADATA_CACHE_TTL_SECS,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

struct MetadataCacheEntry<T: Clone> {
    value: T,
    inserted_at: SystemTime,
    expires_at: SystemTime,
}

/// Thread-safe, TTL-based in-memory cache for non-authoritative upstream metadata keyed by
/// `String`.
///
/// The cache is process-local; it must not be used for security-critical single-use protocol state
/// in multi-server deployments.
#[derive(Clone)]
pub struct NonAuthoritativeMetadataCache<T: Clone> {
    entries: Arc<RwLock<HashMap<String, MetadataCacheEntry<T>>>>,
    ttl: Duration,
    max_entries: usize,
}

impl<T: Clone> Default for NonAuthoritativeMetadataCache<T> {
    fn default() -> Self {
        Self::new_non_authoritative()
    }
}

impl<T: Clone> NonAuthoritativeMetadataCache<T> {
    /// Create a non-authoritative metadata cache with the default TTL.
    ///
    /// Process-local storage is acceptable here because upstream metadata can be refreshed and is
    /// not single-use protocol state.
    #[must_use]
    pub fn new_non_authoritative() -> Self {
        Self::with_ttl_secs(DEFAULT_UPSTREAM_METADATA_CACHE_TTL_SECS)
    }

    /// Create a cache with a custom TTL (in seconds).
    #[must_use]
    pub fn with_ttl_secs(ttl_secs: u64) -> Self {
        Self::with_ttl_secs_and_max_entries(ttl_secs, DEFAULT_UPSTREAM_METADATA_CACHE_MAX_ENTRIES)
    }

    /// Create a cache with a custom TTL and entry bound.
    #[must_use]
    pub fn with_ttl_secs_and_max_entries(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
            max_entries: max_entries.max(1),
        }
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    #[must_use]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn try_new_non_authoritative_with_ttl_secs(
        policy_key: &str,
        secs: u64,
    ) -> Result<Self, crate::config::ConfigError> {
        Self::try_new_non_authoritative_with_ttl_secs_and_max_entries(
            policy_key,
            secs,
            "upstream_metadata_cache_max_entries",
            DEFAULT_UPSTREAM_METADATA_CACHE_MAX_ENTRIES as u32,
        )
    }

    pub fn try_new_non_authoritative_with_ttl_secs_and_max_entries(
        ttl_policy_key: &str,
        secs: u64,
        max_entries_policy_key: &str,
        max_entries: u32,
    ) -> Result<Self, crate::config::ConfigError> {
        if !valid_upstream_metadata_cache_ttl_secs(secs) {
            return Err(crate::config::ConfigError::InvalidNumberRange {
                key: ttl_policy_key.to_string(),
                value: secs.to_string(),
                expectation: "a value in 1..=86400 seconds".to_string(),
            });
        }
        if !valid_upstream_metadata_cache_max_entries(max_entries) {
            return Err(crate::config::ConfigError::InvalidNumberRange {
                key: max_entries_policy_key.to_string(),
                value: max_entries.to_string(),
                expectation: "a value in 1..=1000000 entries".to_string(),
            });
        }
        Ok(Self::with_ttl_secs_and_max_entries(
            secs,
            max_entries as usize,
        ))
    }

    /// Return a clone of the cached value if it exists and has not expired.
    #[must_use]
    #[cfg(test)]
    pub fn get(&self, key: &str) -> Option<T> {
        self.try_get(key)
            .expect("test metadata cache get should succeed")
    }

    /// Return a clone of the cached value if it exists and has not expired.
    pub fn try_get(&self, key: &str) -> Result<Option<T>, String> {
        let entries = self
            .entries
            .read()
            .map_err(|err| format!("metadata cache lock poisoned: {err}"))?;
        let Some(entry) = entries.get(key) else {
            return Ok(None);
        };
        // Strict `<` so entries expiring exactly at `now` are treated as expired.
        if SystemTime::now() < entry.expires_at {
            Ok(Some(entry.value.clone()))
        } else {
            Ok(None)
        }
    }

    #[cfg(test)]
    pub fn insert(&self, key: &str, value: T) {
        self.try_insert(key, value)
            .expect("test metadata cache insert should succeed");
    }

    pub fn try_insert(&self, key: &str, value: T) -> Result<(), String> {
        let inserted_at = SystemTime::now();
        let Some(expires_at) = inserted_at.checked_add(self.ttl) else {
            return Err("TTL expiration cannot be represented".to_string());
        };
        let mut entries = self
            .entries
            .write()
            .map_err(|err| format!("metadata cache lock poisoned: {err}"))?;
        retain_fresh_entries(&mut entries, inserted_at);
        evict_one_if_full(&mut entries, self.max_entries, key);
        entries.insert(
            key.to_string(),
            MetadataCacheEntry {
                value,
                inserted_at,
                expires_at,
            },
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn invalidate(&self, key: &str) {
        self.try_invalidate(key)
            .expect("test metadata cache invalidate should succeed");
    }

    pub fn try_invalidate(&self, key: &str) -> Result<(), String> {
        let mut entries = self
            .entries
            .write()
            .map_err(|err| format!("metadata cache lock poisoned: {err}"))?;
        entries.remove(key);
        Ok(())
    }

    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test metadata cache cleanup should succeed");
    }

    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        let mut entries = self
            .entries
            .write()
            .map_err(|err| format!("metadata cache lock poisoned: {err}"))?;
        let now = SystemTime::now();
        entries.retain(|_, entry| entry.expires_at > now);
        Ok(())
    }

    #[cfg(test)]
    pub fn len(&self) -> Result<usize, String> {
        let entries = self
            .entries
            .read()
            .map_err(|err| format!("metadata cache test helper could not read entries: {err}"))?;
        Ok(entries.len())
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> Result<bool, String> {
        self.len().map(|len| len == 0)
    }
}

fn retain_fresh_entries<T: Clone>(
    entries: &mut HashMap<String, MetadataCacheEntry<T>>,
    now: SystemTime,
) {
    entries.retain(|_, entry| entry.expires_at > now);
}

fn evict_one_if_full<T: Clone>(
    entries: &mut HashMap<String, MetadataCacheEntry<T>>,
    max_entries: usize,
    incoming_key: &str,
) {
    if entries.len() < max_entries || entries.contains_key(incoming_key) {
        return;
    }
    if let Some(evict_key) = entries
        .iter()
        .min_by(|(left_key, left), (right_key, right)| {
            left.expires_at
                .cmp(&right.expires_at)
                .then_with(|| left.inserted_at.cmp(&right.inserted_at))
                .then_with(|| left_key.cmp(right_key))
        })
        .map(|(key, _)| key.clone())
    {
        entries.remove(&evict_key);
    }
}
