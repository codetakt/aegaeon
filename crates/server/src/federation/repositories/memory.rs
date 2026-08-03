use serde_json::Value;
use uuid::Uuid;

use crate::federation::FederationError;

use super::clock::current_unix_epoch_secs;
use super::config::DEFAULT_FEDERATION_CACHE_MAX_ENTRIES;
use super::traits::{
    EntityCacheRepository, RepositoryFuture, TrustAnchorRepository, TrustChainCacheRepository,
};
use super::types::{StoredEntityCache, StoredTrustAnchor, StoredTrustChain};

/// In-memory trust anchor repository for unit testing.
pub struct InMemoryTrustAnchorRepo {
    anchors: std::sync::RwLock<Vec<StoredTrustAnchor>>,
}

impl Default for InMemoryTrustAnchorRepo {
    fn default() -> Self {
        Self {
            anchors: std::sync::RwLock::new(Vec::new()),
        }
    }
}

impl InMemoryTrustAnchorRepo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list_for_environment(
        &self,
        environment_id: Uuid,
    ) -> Result<Vec<StoredTrustAnchor>, FederationError> {
        let anchors = self
            .anchors
            .read()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;
        Ok(anchors
            .iter()
            .filter(|a| a.environment_id == environment_id)
            .cloned()
            .collect())
    }

    pub fn get(
        &self,
        environment_id: Uuid,
        entity_id: &str,
    ) -> Result<Option<StoredTrustAnchor>, FederationError> {
        let anchors = self
            .anchors
            .read()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;
        Ok(anchors
            .iter()
            .find(|a| a.environment_id == environment_id && a.entity_id == entity_id)
            .cloned())
    }

    pub fn upsert(
        &self,
        environment_id: Uuid,
        entity_id: &str,
        jwks: &Value,
        metadata_policy: Option<&Value>,
    ) -> Result<StoredTrustAnchor, FederationError> {
        let mut anchors = self
            .anchors
            .write()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;

        let now = current_unix_epoch_secs()?;

        if let Some(existing) = anchors
            .iter_mut()
            .find(|a| a.environment_id == environment_id && a.entity_id == entity_id)
        {
            existing.jwks = jwks.clone();
            existing.metadata_policy = metadata_policy.cloned();
            existing.updated_at = now;
            return Ok(existing.clone());
        }

        let anchor = StoredTrustAnchor {
            id: Uuid::new_v4(),
            environment_id,
            entity_id: entity_id.to_string(),
            jwks: jwks.clone(),
            metadata_policy: metadata_policy.cloned(),
            created_at: now,
            updated_at: now,
        };
        anchors.push(anchor.clone());
        Ok(anchor)
    }

    pub fn delete(&self, environment_id: Uuid, entity_id: &str) -> Result<bool, FederationError> {
        let mut anchors = self
            .anchors
            .write()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;
        let before = anchors.len();
        anchors.retain(|a| !(a.environment_id == environment_id && a.entity_id == entity_id));
        Ok(anchors.len() < before)
    }
}

impl TrustAnchorRepository for InMemoryTrustAnchorRepo {
    fn list_for_environment(
        &self,
        environment_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<StoredTrustAnchor>> {
        Box::pin(async move { self.list_for_environment(environment_id) })
    }

    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
    ) -> RepositoryFuture<'a, Option<StoredTrustAnchor>> {
        Box::pin(async move { self.get(environment_id, entity_id) })
    }

    fn upsert<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
        jwks: &'a Value,
        metadata_policy: Option<&'a Value>,
    ) -> RepositoryFuture<'a, StoredTrustAnchor> {
        Box::pin(async move { self.upsert(environment_id, entity_id, jwks, metadata_policy) })
    }

    fn delete<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move { self.delete(environment_id, entity_id) })
    }
}

/// In-memory entity cache repository for unit testing.
///
/// Supports a configurable `max_entries` limit (P8-CACHE-1). When the limit
/// is reached on insert, the entry with the earliest `fetched_at` timestamp
/// is evicted (LRU approximation).
pub struct InMemoryEntityCacheRepo {
    entries: std::sync::RwLock<Vec<StoredEntityCache>>,
    pub(in crate::federation) max_entries: usize,
}

impl Default for InMemoryEntityCacheRepo {
    fn default() -> Self {
        Self {
            entries: std::sync::RwLock::new(Vec::new()),
            max_entries: DEFAULT_FEDERATION_CACHE_MAX_ENTRIES,
        }
    }
}

impl InMemoryEntityCacheRepo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    pub fn get(
        &self,
        environment_id: Uuid,
        entity_id: &str,
        now_epoch_secs: i64,
    ) -> Result<Option<StoredEntityCache>, FederationError> {
        let entries = self
            .entries
            .read()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;
        Ok(entries
            .iter()
            .find(|e| {
                e.environment_id == environment_id
                    && e.entity_id == entity_id
                    && e.expires_at > now_epoch_secs
            })
            .cloned())
    }

    pub fn upsert(
        &self,
        environment_id: Uuid,
        entity_id: &str,
        jws: &str,
        parsed: &Value,
        expires_at_epoch_secs: i64,
    ) -> Result<(), FederationError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;

        let now = current_unix_epoch_secs()?;

        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.environment_id == environment_id && e.entity_id == entity_id)
        {
            existing.entity_configuration_jws = jws.to_string();
            existing.parsed_statement = parsed.clone();
            existing.fetched_at = now;
            existing.expires_at = expires_at_epoch_secs;
            return Ok(());
        }

        // LRU eviction (P8-CACHE-1): if at capacity, remove the entry with
        // the earliest fetched_at timestamp.
        if entries.len() >= self.max_entries {
            if let Some(oldest_idx) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.fetched_at)
                .map(|(i, _)| i)
            {
                entries.swap_remove(oldest_idx);
            }
        }

        entries.push(StoredEntityCache {
            id: Uuid::new_v4(),
            environment_id,
            entity_id: entity_id.to_string(),
            entity_configuration_jws: jws.to_string(),
            parsed_statement: parsed.clone(),
            fetched_at: now,
            expires_at: expires_at_epoch_secs,
        });
        Ok(())
    }

    pub fn cleanup_expired(&self, now_epoch_secs: i64) -> Result<u64, FederationError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;
        let before = entries.len();
        entries.retain(|e| e.expires_at > now_epoch_secs);
        Ok((before - entries.len()) as u64)
    }
}

impl EntityCacheRepository for InMemoryEntityCacheRepo {
    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
        now_epoch_secs: i64,
    ) -> RepositoryFuture<'a, Option<StoredEntityCache>> {
        Box::pin(async move { self.get(environment_id, entity_id, now_epoch_secs) })
    }

    fn upsert<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
        jws: &'a str,
        parsed: &'a Value,
        expires_at_epoch_secs: i64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.upsert(
                environment_id,
                entity_id,
                jws,
                parsed,
                expires_at_epoch_secs,
            )
        })
    }

    fn cleanup_expired(&self, now_epoch_secs: i64) -> RepositoryFuture<'_, u64> {
        Box::pin(async move { self.cleanup_expired(now_epoch_secs) })
    }
}

/// In-memory trust chain cache repository for unit testing.
///
/// Supports a configurable `max_entries` limit (P8-CACHE-1). When the limit
/// is reached on insert, the entry with the earliest `resolved_at` timestamp
/// is evicted (LRU approximation).
pub struct InMemoryTrustChainCacheRepo {
    entries: std::sync::RwLock<Vec<StoredTrustChain>>,
    pub(in crate::federation) max_entries: usize,
}

impl Default for InMemoryTrustChainCacheRepo {
    fn default() -> Self {
        Self {
            entries: std::sync::RwLock::new(Vec::new()),
            max_entries: DEFAULT_FEDERATION_CACHE_MAX_ENTRIES,
        }
    }
}

impl InMemoryTrustChainCacheRepo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    pub fn get(
        &self,
        environment_id: Uuid,
        leaf_entity_id: &str,
        anchor_entity_id: &str,
        now_epoch_secs: i64,
    ) -> Result<Option<StoredTrustChain>, FederationError> {
        let entries = self
            .entries
            .read()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;
        Ok(entries
            .iter()
            .find(|e| {
                e.environment_id == environment_id
                    && e.leaf_entity_id == leaf_entity_id
                    && e.anchor_entity_id == anchor_entity_id
                    && e.expires_at > now_epoch_secs
            })
            .cloned())
    }

    pub fn upsert(
        &self,
        environment_id: Uuid,
        leaf_entity_id: &str,
        anchor_entity_id: &str,
        chain_jwts: &Value,
        expires_at_epoch_secs: i64,
    ) -> Result<(), FederationError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;

        let now = current_unix_epoch_secs()?;

        if let Some(existing) = entries.iter_mut().find(|e| {
            e.environment_id == environment_id
                && e.leaf_entity_id == leaf_entity_id
                && e.anchor_entity_id == anchor_entity_id
        }) {
            existing.chain_jwts = chain_jwts.clone();
            existing.resolved_at = now;
            existing.expires_at = expires_at_epoch_secs;
            return Ok(());
        }

        // LRU eviction (P8-CACHE-1): if at capacity, remove the entry with
        // the earliest resolved_at timestamp.
        if entries.len() >= self.max_entries {
            if let Some(oldest_idx) = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.resolved_at)
                .map(|(i, _)| i)
            {
                entries.swap_remove(oldest_idx);
            }
        }

        entries.push(StoredTrustChain {
            id: Uuid::new_v4(),
            environment_id,
            leaf_entity_id: leaf_entity_id.to_string(),
            anchor_entity_id: anchor_entity_id.to_string(),
            chain_jwts: chain_jwts.clone(),
            resolved_at: now,
            expires_at: expires_at_epoch_secs,
        });
        Ok(())
    }

    pub fn cleanup_expired(&self, now_epoch_secs: i64) -> Result<u64, FederationError> {
        let mut entries = self
            .entries
            .write()
            .map_err(|e| FederationError::Fetch(format!("lock poisoned: {e}")))?;
        let before = entries.len();
        entries.retain(|e| e.expires_at > now_epoch_secs);
        Ok((before - entries.len()) as u64)
    }
}

impl TrustChainCacheRepository for InMemoryTrustChainCacheRepo {
    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        leaf_entity_id: &'a str,
        anchor_entity_id: &'a str,
        now_epoch_secs: i64,
    ) -> RepositoryFuture<'a, Option<StoredTrustChain>> {
        Box::pin(async move {
            self.get(
                environment_id,
                leaf_entity_id,
                anchor_entity_id,
                now_epoch_secs,
            )
        })
    }

    fn upsert<'a>(
        &'a self,
        environment_id: Uuid,
        leaf_entity_id: &'a str,
        anchor_entity_id: &'a str,
        chain_jwts: &'a Value,
        expires_at_epoch_secs: i64,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.upsert(
                environment_id,
                leaf_entity_id,
                anchor_entity_id,
                chain_jwts,
                expires_at_epoch_secs,
            )
        })
    }

    fn cleanup_expired(&self, now_epoch_secs: i64) -> RepositoryFuture<'_, u64> {
        Box::pin(async move { self.cleanup_expired(now_epoch_secs) })
    }
}
