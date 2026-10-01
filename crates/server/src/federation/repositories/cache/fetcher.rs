use std::time::Duration;
use uuid::Uuid;

use crate::federation::admission::{admit_subordinate_statement, validate_authority_configuration};
use crate::federation::{
    admit_entity_configuration, validate_entity_statement, EntityStatement, FederationError,
    FederationFetcher, JwkSet,
};

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
/// 2. If hit, reverify the raw JWS, requested identity and current time.
/// 3. If miss, require retained raw JWS and admit it before caching and returning.
///
/// Decoded-only fetchers must override the retained-JWS methods to use this wrapper.
/// Detached parsed fields never authorize returned or cached metadata.
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
        self.fetch_entity_configuration_with_clock(entity_id, current_unix_epoch_secs)
            .await
    }

    pub(in crate::federation) async fn fetch_entity_configuration_with_clock(
        &self,
        entity_id: &str,
        clock: impl Fn() -> Result<i64, FederationError>,
    ) -> Result<EntityStatement, FederationError> {
        let cached = self
            .cache
            .get(self.environment_id, entity_id, clock()?)
            .await?;
        let now = clock()?;
        if let Some(cached) = cached {
            let admitted = if cached.environment_id != self.environment_id
                || cached.entity_id != entity_id
                || cached.expires_at <= now
            {
                Err(FederationError::Validation(
                    "cached entity configuration does not match scope or lifetime".into(),
                ))
            } else {
                reconstruct_entity_configuration_from_cache(&cached, entity_id, now)
            };
            match admitted {
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
        let entity_configuration_jws = fetched.entity_configuration_jws.ok_or_else(|| {
            FederationError::Validation(
                "entity configuration fetcher must retain compact JWS".into(),
            )
        })?;
        let now = clock()?;
        let stmt = admit_entity_configuration(&entity_configuration_jws, entity_id, now)?;
        let expires_at = entity_cache_expires_at(now, self.cache_ttl, &stmt)?;
        if expires_at > now {
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
            validate_entity_statement(&stmt, clock()?)?;
        }

        Ok(stmt)
    }

    /// Fetch and contextually admit a subordinate statement from retained raw JWS.
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
        self.fetch_subordinate_statement_with_clock(
            authority_entity_id,
            authority_config,
            subordinate_entity_id,
            issuer_jwks,
            current_unix_epoch_secs,
        )
        .await
    }

    pub(in crate::federation) async fn fetch_subordinate_statement_with_clock(
        &self,
        authority_entity_id: &str,
        authority_config: &EntityStatement,
        subordinate_entity_id: &str,
        issuer_jwks: &JwkSet,
        clock: impl Fn() -> Result<i64, FederationError>,
    ) -> Result<EntityStatement, FederationError> {
        validate_authority_configuration(authority_config, authority_entity_id, clock()?)?;
        let fetched = self
            .inner
            .fetch_subordinate_statement_with_jws(
                authority_entity_id,
                authority_config,
                subordinate_entity_id,
                issuer_jwks,
            )
            .await?;
        let now = clock()?;
        validate_authority_configuration(authority_config, authority_entity_id, now)?;
        let jws = fetched.subordinate_statement_jws.ok_or_else(|| {
            FederationError::Validation(
                "subordinate statement fetcher must retain compact JWS".into(),
            )
        })?;
        admit_subordinate_statement(
            &jws,
            authority_entity_id,
            subordinate_entity_id,
            issuer_jwks,
            now,
        )
    }
}
