use std::future::Future;
use uuid::Uuid;

use crate::federation::trust_chain::resolve_trust_chain_with_jwts;
use crate::federation::{
    FederationError, FederationFetcher, ResolvedTrustChain, TrustAnchor, TrustChain,
};

use super::super::config::FederationCacheConfig;
use super::super::traits::{TrustAnchorRepository, TrustChainCacheRepository};
use super::super::types::StoredTrustAnchor;
use super::expiry::trust_chain_cache_expires_at;
use super::metrics::{
    record_federation_cache_validation_failure, record_federation_cache_write_failure,
};
use super::reconstruction::{
    cached_chain_jwts_owned, chain_jwts_to_value, reconstruct_chain_from_cache,
    validate_cached_trust_chain, validate_resolved_chain_jws_alignment,
};

/// Resolve a trust chain with caching support using a [`FederationFetcher`].
///
/// Checks the trust chain cache first. On miss, resolves via the provided
/// fetcher and stores the result.
///
/// # Errors
///
/// Returns [`FederationError`] when repository access fails, trust anchors are missing, fresh
/// resolution fails, or the cache cannot be updated.
pub async fn resolve_trust_chain_cached(
    leaf_entity_id: &str,
    environment_id: Uuid,
    trust_anchor_repo: &dyn TrustAnchorRepository,
    chain_cache: &dyn TrustChainCacheRepository,
    fetcher: &dyn FederationFetcher,
    config: &FederationCacheConfig,
    now: i64,
) -> Result<TrustChain, FederationError> {
    resolve_trust_chain_cached_with(
        leaf_entity_id,
        environment_id,
        trust_anchor_repo,
        chain_cache,
        config,
        now,
        |trust_anchors| async move {
            resolve_trust_chain_with_jwts(leaf_entity_id, &trust_anchors, fetcher, now).await
        },
    )
    .await
}

/// Resolve a trust chain with cache support and a caller-provided fresh resolver.
///
/// This keeps repository I/O async while allowing callers to provide a fresh resolver. Web paths
/// use the async federation transport directly; unit tests can provide a pure in-process resolver.
///
/// # Errors
///
/// Returns [`FederationError`] when repository access fails, trust anchors are missing, fresh
/// resolution fails, or the cache cannot be updated.
pub async fn resolve_trust_chain_cached_with<F, Fut>(
    leaf_entity_id: &str,
    environment_id: Uuid,
    trust_anchor_repo: &dyn TrustAnchorRepository,
    chain_cache: &dyn TrustChainCacheRepository,
    config: &FederationCacheConfig,
    now: i64,
    resolve_fresh: F,
) -> Result<TrustChain, FederationError>
where
    F: FnMut(Vec<TrustAnchor>) -> Fut,
    Fut: Future<Output = Result<ResolvedTrustChain, FederationError>>,
{
    let stored_anchors = trust_anchor_repo
        .list_for_environment(environment_id)
        .await?;
    let trust_anchors: Vec<TrustAnchor> = stored_anchors
        .iter()
        .map(StoredTrustAnchor::to_trust_anchor)
        .collect::<Result<_, _>>()?;

    if trust_anchors.is_empty() {
        return Err(FederationError::ChainResolution(
            "no trust anchors configured for this environment".into(),
        ));
    }

    resolve_trust_chain_jwts_cached_with(
        leaf_entity_id,
        environment_id,
        trust_anchors,
        chain_cache,
        config,
        now,
        resolve_fresh,
    )
    .await
    .map(ResolvedTrustChain::into_trust_chain)
}

/// Resolve a trust chain with cache support while retaining the compact JWS chain.
///
/// This is used by federation resolve endpoints, where the response contract requires returning
/// the verified compact Entity Statements rather than only the semantic chain.
///
/// # Errors
///
/// Returns [`FederationError`] when repository access fails, trust anchors are missing, fresh
/// resolution fails, or the cache cannot be updated.
pub async fn resolve_trust_chain_jwts_cached_with<F, Fut>(
    leaf_entity_id: &str,
    environment_id: Uuid,
    trust_anchors: Vec<TrustAnchor>,
    chain_cache: &dyn TrustChainCacheRepository,
    config: &FederationCacheConfig,
    now: i64,
    mut resolve_fresh: F,
) -> Result<ResolvedTrustChain, FederationError>
where
    F: FnMut(Vec<TrustAnchor>) -> Fut,
    Fut: Future<Output = Result<ResolvedTrustChain, FederationError>>,
{
    if trust_anchors.is_empty() {
        return Err(FederationError::ChainResolution(
            "no trust anchors configured for this environment".into(),
        ));
    }

    let mut last_error = None;
    for anchor in trust_anchors {
        if let Some(cached) = chain_cache
            .get(environment_id, leaf_entity_id, &anchor.entity_id, now)
            .await?
        {
            match reconstruct_cached_resolved_trust_chain(&cached, &anchor, now) {
                Ok(resolved) => return Ok(resolved),
                Err(error) => {
                    record_federation_cache_validation_failure("trust_chain");
                    tracing::warn!(
                        %environment_id,
                        leaf_entity_id,
                        anchor_entity_id = %anchor.entity_id,
                        error = %error,
                        "cached federation trust chain failed JWS revalidation; resolving fresh"
                    );
                }
            }
        }

        match resolve_fresh(vec![anchor.clone()]).await {
            Ok(resolved) => {
                validate_resolved_chain_jws_alignment(&resolved)?;

                let chain_jwts = chain_jwts_to_value(&resolved.chain_jwts);
                let expires_at = trust_chain_cache_expires_at(
                    now,
                    config.trust_chain_cache_ttl,
                    &resolved.trust_chain.chain,
                )?;
                if let Err(error) = chain_cache
                    .upsert(
                        environment_id,
                        leaf_entity_id,
                        &resolved.trust_chain.anchor.entity_id,
                        &chain_jwts,
                        expires_at,
                    )
                    .await
                {
                    record_federation_cache_write_failure("trust_chain");
                    tracing::warn!(
                        %environment_id,
                        leaf_entity_id,
                        anchor_entity_id = %resolved.trust_chain.anchor.entity_id,
                        error = %error,
                        "federation trust-chain cache write failed"
                    );
                }

                return Ok(resolved);
            }
            Err(error) => {
                tracing::debug!(
                    %environment_id,
                    leaf_entity_id,
                    anchor_entity_id = %anchor.entity_id,
                    error = %error,
                    "fresh federation trust-chain resolution failed for requested anchor"
                );
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        FederationError::ChainResolution("no trust anchors configured for this environment".into())
    }))
}

fn reconstruct_cached_resolved_trust_chain(
    cached: &super::super::types::StoredTrustChain,
    anchor: &TrustAnchor,
    now: i64,
) -> Result<ResolvedTrustChain, FederationError> {
    let chain = reconstruct_chain_from_cache(cached, anchor)
        .and_then(|chain| validate_cached_trust_chain(chain, cached, now))?;
    let chain_jwts = cached_chain_jwts_owned(&cached.chain_jwts)?;
    let resolved = ResolvedTrustChain::new(chain, chain_jwts);
    validate_resolved_chain_jws_alignment(&resolved)?;
    Ok(resolved)
}
