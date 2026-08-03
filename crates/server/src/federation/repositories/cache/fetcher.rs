use std::time::Duration;
use uuid::Uuid;

use crate::federation::{EntityStatement, FederationError, FederationFetcher, JwkSet};

use super::super::clock::current_unix_epoch_secs;
use super::super::config::FederationCacheConfig;
use super::super::traits::EntityCacheRepository;
use super::expiry::entity_cache_expires_at;
use super::metrics::{
    record_federation_cache_validation_failure, record_federation_cache_write_failure,
};
use super::reconstruction::reconstruct_entity_configuration_from_cache;

/// A [`FederationFetcher`] wrapper that caches entity configurations in an
/// [`EntityCacheRepository`].
///
/// On each `fetch_entity_configuration` call:
/// 1. Check the cache for a valid non-expired entry.
/// 2. If hit, parse the cached JWS and return the statement.
/// 3. If miss, delegate to the inner fetcher, cache the result, and return.
///
/// Subordinate statements are not cached because they are fetched with a
/// specific issuer JWKS context and are typically one-shot during chain
/// resolution.
pub struct CachedFederationFetcher<F: FederationFetcher> {
    inner: F,
    cache: Box<dyn EntityCacheRepository>,
    environment_id: Uuid,
    cache_ttl: Duration,
}

impl<F: FederationFetcher> CachedFederationFetcher<F> {
    pub fn new(
        inner: F,
        cache: Box<dyn EntityCacheRepository>,
        environment_id: Uuid,
        config: &FederationCacheConfig,
    ) -> Self {
        Self {
            inner,
            cache,
            environment_id,
            cache_ttl: config.entity_cache_ttl,
        }
    }

    /// Fetch an entity configuration through the entity cache.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when cache access, parsing, validation, or the inner fetcher fails.
    pub async fn fetch_entity_configuration(
        &self,
        entity_id: &str,
    ) -> Result<EntityStatement, FederationError> {
        let now = current_unix_epoch_secs()?;

        if let Some(cached) = self.cache.get(self.environment_id, entity_id, now).await? {
            match reconstruct_entity_configuration_from_cache(&cached, entity_id, now) {
                Ok(stmt) => return Ok(stmt),
                Err(error) => {
                    record_federation_cache_validation_failure("entity_configuration");
                    tracing::warn!(
                        environment_id = %self.environment_id,
                        entity_id,
                        error = %error,
                        "cached federation entity configuration failed JWS revalidation; refetching"
                    );
                }
            }
        }

        let fetched = self
            .inner
            .fetch_entity_configuration_with_jws(entity_id)
            .await?;
        let stmt = fetched.statement;

        if let Some(entity_configuration_jws) = fetched.entity_configuration_jws {
            let expires_at = entity_cache_expires_at(now, self.cache_ttl, &stmt)?;
            let parsed = serde_json::to_value(&stmt)?;
            if let Err(error) = self
                .cache
                .upsert(
                    self.environment_id,
                    entity_id,
                    &entity_configuration_jws,
                    &parsed,
                    expires_at,
                )
                .await
            {
                record_federation_cache_write_failure("entity_configuration");
                tracing::warn!(
                    environment_id = %self.environment_id,
                    entity_id,
                    error = %error,
                    "federation entity cache write failed"
                );
            }
        } else {
            tracing::debug!(
                environment_id = %self.environment_id,
                entity_id,
                "federation entity cache write skipped because fetcher did not retain compact JWS"
            );
        }

        Ok(stmt)
    }

    /// Fetch a subordinate statement directly through the inner fetcher.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError`] when the inner fetcher cannot retrieve or verify the statement.
    pub async fn fetch_subordinate_statement(
        &self,
        authority_entity_id: &str,
        authority_config: &EntityStatement,
        subordinate_entity_id: &str,
        issuer_jwks: &JwkSet,
    ) -> Result<EntityStatement, FederationError> {
        self.inner
            .fetch_subordinate_statement(
                authority_entity_id,
                authority_config,
                subordinate_entity_id,
                issuer_jwks,
            )
            .await
    }
}
