use serde_json::Value;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

use crate::federation::FederationError;

use super::types::{StoredEntityCache, StoredTrustAnchor, StoredTrustChain};

pub type RepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, FederationError>> + Send + 'a>>;

/// Repository for configured trust anchors.
pub trait TrustAnchorRepository: Send + Sync {
    /// List all trust anchors for an environment.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn list_for_environment(
        &self,
        environment_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<StoredTrustAnchor>>;

    /// Get a specific trust anchor by environment and `entity_id`.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
    ) -> RepositoryFuture<'a, Option<StoredTrustAnchor>>;

    /// Insert or update a trust anchor (upsert on `environment_id` + `entity_id`).
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn upsert<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
        jwks: &'a Value,
        metadata_policy: Option<&'a Value>,
    ) -> RepositoryFuture<'a, StoredTrustAnchor>;

    /// Delete a trust anchor.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn delete<'a>(&'a self, environment_id: Uuid, entity_id: &'a str)
        -> RepositoryFuture<'a, bool>;
}

/// Repository for cached entity configurations.
pub trait EntityCacheRepository: Send + Sync {
    /// Get a cached entity configuration if it exists and has not expired.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
        now_epoch_secs: i64,
    ) -> RepositoryFuture<'a, Option<StoredEntityCache>>;

    /// Insert or update a cached entity configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn upsert<'a>(
        &'a self,
        environment_id: Uuid,
        entity_id: &'a str,
        jws: &'a str,
        parsed: &'a Value,
        expires_at_epoch_secs: i64,
    ) -> RepositoryFuture<'a, ()>;

    /// Remove expired entries.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn cleanup_expired(&self, now_epoch_secs: i64) -> RepositoryFuture<'_, u64>;
}

/// Repository for cached resolved trust chains.
pub trait TrustChainCacheRepository: Send + Sync {
    /// Get a cached trust chain if it exists and has not expired.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn get<'a>(
        &'a self,
        environment_id: Uuid,
        leaf_entity_id: &'a str,
        anchor_entity_id: &'a str,
        now_epoch_secs: i64,
    ) -> RepositoryFuture<'a, Option<StoredTrustChain>>;

    /// Insert or update a cached trust chain.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn upsert<'a>(
        &'a self,
        environment_id: Uuid,
        leaf_entity_id: &'a str,
        anchor_entity_id: &'a str,
        chain_jwts: &'a Value,
        expires_at_epoch_secs: i64,
    ) -> RepositoryFuture<'a, ()>;

    /// Remove expired entries.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when repository access fails.
    fn cleanup_expired(&self, now_epoch_secs: i64) -> RepositoryFuture<'_, u64>;
}
