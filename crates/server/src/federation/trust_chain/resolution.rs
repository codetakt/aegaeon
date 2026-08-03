use super::super::{
    validate_entity_statement, EntityStatement, FederationError, FederationFetcher,
    ResolvedTrustChain, TrustAnchor, TrustChain, MAX_CHAIN_DEPTH,
};
use super::anchor_resolution::{
    try_resolve_via_trust_anchor, try_resolve_via_trust_anchor_with_jwts,
};
use super::intermediate_resolution::{
    try_resolve_via_intermediate, try_resolve_via_intermediate_with_jwts,
};
use super::link::validate_entity_configuration_link;
use super::path_constraints::{enforce_authority_hint_timeout, leaf_entity_types};
use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const MAX_AUTHORITY_HINTS_PER_STATEMENT: usize = 16;
const MAX_AUTHORITY_HINT_ATTEMPTS_PER_RESOLUTION: usize = 64;
const MAX_TRUST_CHAIN_RESOLUTION_DURATION: Duration = Duration::from_secs(30);

pub(super) type TrustChainResolutionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(super) struct ChainResolutionContext<'a> {
    pub(super) anchor_map: &'a HashMap<&'a str, &'a TrustAnchor>,
    pub(super) fetcher: &'a dyn FederationFetcher,
    pub(super) now: i64,
    pub(super) leaf_entity_types: BTreeSet<String>,
    authority_hint_attempts: AtomicUsize,
    started_at: Instant,
}

impl<'a> ChainResolutionContext<'a> {
    fn new(
        anchor_map: &'a HashMap<&'a str, &'a TrustAnchor>,
        fetcher: &'a dyn FederationFetcher,
        now: i64,
        leaf_entity_types: BTreeSet<String>,
    ) -> Self {
        Self {
            anchor_map,
            fetcher,
            now,
            leaf_entity_types,
            authority_hint_attempts: AtomicUsize::new(0),
            started_at: Instant::now(),
        }
    }

    fn enforce_authority_hints_budget(
        &self,
        current_entity_id: &str,
        authority_hints: &[String],
        depth: usize,
    ) -> Result<(), FederationError> {
        if authority_hints.len() > MAX_AUTHORITY_HINTS_PER_STATEMENT {
            tracing::warn!(
                current_entity_id,
                depth,
                authority_hint_count = authority_hints.len(),
                max_authority_hints = MAX_AUTHORITY_HINTS_PER_STATEMENT,
                "federation trust-chain authority_hints fanout exceeded"
            );
            return Err(FederationError::ChainResolution(format!(
                "too many authority_hints for {current_entity_id} at depth {depth}"
            )));
        }
        self.enforce_resolution_deadline(current_entity_id, depth)
    }

    fn record_authority_hint_attempt(
        &self,
        current_entity_id: &str,
        authority_id: &str,
        depth: usize,
    ) -> Result<(), FederationError> {
        self.enforce_resolution_deadline(current_entity_id, depth)?;
        let attempts = self
            .authority_hint_attempts
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if attempts > MAX_AUTHORITY_HINT_ATTEMPTS_PER_RESOLUTION {
            tracing::warn!(
                current_entity_id,
                authority_id,
                depth,
                attempts,
                max_attempts = MAX_AUTHORITY_HINT_ATTEMPTS_PER_RESOLUTION,
                "federation trust-chain authority_hints total attempt budget exceeded"
            );
            return Err(FederationError::ChainResolution(format!(
                "authority_hints attempt budget exceeded for {current_entity_id}"
            )));
        }
        Ok(())
    }

    fn enforce_resolution_deadline(
        &self,
        current_entity_id: &str,
        depth: usize,
    ) -> Result<(), FederationError> {
        if self.started_at.elapsed() <= MAX_TRUST_CHAIN_RESOLUTION_DURATION {
            return Ok(());
        }
        tracing::warn!(
            current_entity_id,
            depth,
            elapsed_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            max_ms =
                u64::try_from(MAX_TRUST_CHAIN_RESOLUTION_DURATION.as_millis()).unwrap_or(u64::MAX),
            "federation trust-chain total resolution deadline exceeded"
        );
        Err(FederationError::ChainResolution(format!(
            "trust-chain resolution deadline exceeded for {current_entity_id}"
        )))
    }

    fn authority_hint_revisits_path(
        &self,
        chain: &[EntityStatement],
        current_entity_id: &str,
        authority_id: &str,
        depth: usize,
    ) -> bool {
        let revisits = chain
            .iter()
            .step_by(2)
            .filter(|statement| statement.iss == statement.sub)
            .any(|statement| statement.iss == authority_id);
        if revisits {
            tracing::warn!(
                current_entity_id,
                authority_id,
                depth,
                "federation trust-chain authority_hints cycle rejected"
            );
        }
        revisits
    }
}

/// Resolve a trust chain from a leaf entity to a configured trust anchor.
///
/// Implements the trust chain resolution algorithm from `OpenID` Federation §4:
/// 1. Fetch the leaf's entity configuration
/// 2. Follow `authority_hints` upward
/// 3. At each level, fetch the subordinate statement + authority's config
/// 4. Stop when a configured trust anchor is reached
///
/// Enforces Tamarin properties:
/// - `chain_to_trust_anchor`: chain terminates at a configured trust anchor
/// - `intermediate_chain_key_authenticity`: all signatures verified by fetcher
/// - `no_trust_without_chain`: only returns after successful chain resolution
///
/// # Errors
///
/// Returns [`FederationError`] when the leaf statement, subordinate statements, or trust anchor
/// configuration cannot be fetched, verified, or composed into a valid trust chain.
pub async fn resolve_trust_chain(
    leaf_entity_id: &str,
    trust_anchors: &[TrustAnchor],
    fetcher: &dyn FederationFetcher,
    now: i64,
) -> Result<TrustChain, FederationError> {
    let anchor_map: HashMap<&str, &TrustAnchor> = trust_anchors
        .iter()
        .map(|ta| (ta.entity_id.as_str(), ta))
        .collect();

    let leaf_config = fetcher.fetch_entity_configuration(leaf_entity_id).await?;
    validate_entity_statement(&leaf_config, now)?;
    validate_entity_configuration_link(&leaf_config, leaf_entity_id)?;
    let leaf_entity_types = leaf_entity_types(&leaf_config);

    let authority_hints = leaf_config
        .authority_hints
        .clone()
        .ok_or(FederationError::MissingField("authority_hints"))?;

    let mut chain = vec![leaf_config];
    let ctx = ChainResolutionContext::new(&anchor_map, fetcher, now, leaf_entity_types);

    let anchor = resolve_chain_up(
        &mut chain,
        leaf_entity_id.to_string(),
        authority_hints,
        &ctx,
        0,
    )
    .await?;

    Ok(TrustChain { chain, anchor })
}

/// Resolve a trust chain and retain the compact JWS artifacts that were actually verified.
///
/// This is the canonical resolver for persistent trust-chain cache writes. The semantic
/// [`TrustChain`] is still returned for callers, while `chain_jwts` preserves the cryptographic
/// evidence needed to reconstruct the chain without trusting parsed database JSON.
///
/// # Errors
///
/// Returns [`FederationError`] when resolution fails or the selected fetcher cannot provide the
/// compact JWS values required for cacheable federation evidence.
pub async fn resolve_trust_chain_with_jwts(
    leaf_entity_id: &str,
    trust_anchors: &[TrustAnchor],
    fetcher: &dyn FederationFetcher,
    now: i64,
) -> Result<ResolvedTrustChain, FederationError> {
    let anchor_map: HashMap<&str, &TrustAnchor> = trust_anchors
        .iter()
        .map(|ta| (ta.entity_id.as_str(), ta))
        .collect();

    let fetched_leaf = fetcher
        .fetch_entity_configuration_with_jws(leaf_entity_id)
        .await?;
    let leaf_jws = require_fetched_jws(
        "leaf entity configuration",
        leaf_entity_id,
        fetched_leaf.entity_configuration_jws,
    )?;
    let leaf_config = fetched_leaf.statement;
    validate_entity_statement(&leaf_config, now)?;
    validate_entity_configuration_link(&leaf_config, leaf_entity_id)?;
    let leaf_entity_types = leaf_entity_types(&leaf_config);

    let authority_hints = leaf_config
        .authority_hints
        .clone()
        .ok_or(FederationError::MissingField("authority_hints"))?;

    let mut chain = vec![leaf_config];
    let mut chain_jwts = vec![leaf_jws];
    let ctx = ChainResolutionContext::new(&anchor_map, fetcher, now, leaf_entity_types);

    let anchor = resolve_chain_up_with_jwts(
        &mut chain,
        &mut chain_jwts,
        leaf_entity_id.to_string(),
        authority_hints,
        &ctx,
        0,
    )
    .await?;

    Ok(ResolvedTrustChain::new(
        TrustChain { chain, anchor },
        chain_jwts,
    ))
}

pub(super) fn resolve_chain_up<'a>(
    chain: &'a mut Vec<EntityStatement>,
    current_entity_id: String,
    authority_hints: Vec<String>,
    ctx: &'a ChainResolutionContext<'a>,
    depth: usize,
) -> TrustChainResolutionFuture<'a, Result<TrustAnchor, FederationError>> {
    Box::pin(async move {
        if depth >= MAX_CHAIN_DEPTH {
            return Err(FederationError::ChainTooDeep);
        }
        ctx.enforce_authority_hints_budget(&current_entity_id, &authority_hints, depth)?;

        let start = Instant::now();

        for authority_id in authority_hints {
            ctx.record_authority_hint_attempt(&current_entity_id, &authority_id, depth)?;
            if ctx.authority_hint_revisits_path(chain, &current_entity_id, &authority_id, depth) {
                continue;
            }
            enforce_authority_hint_timeout(start, &current_entity_id, depth)?;
            let resolved = match ctx.anchor_map.get(authority_id.as_str()) {
                Some(anchor) => {
                    try_resolve_via_trust_anchor(
                        chain,
                        &current_entity_id,
                        &authority_id,
                        anchor,
                        ctx,
                        depth,
                    )
                    .await
                }
                None => {
                    try_resolve_via_intermediate(
                        chain,
                        &current_entity_id,
                        &authority_id,
                        ctx,
                        depth,
                    )
                    .await
                }
            };
            if let Some(anchor) = resolved {
                return Ok(anchor);
            }
        }

        Err(FederationError::ChainResolution(format!(
            "no path from {current_entity_id} to any trust anchor"
        )))
    })
}

pub(super) fn resolve_chain_up_with_jwts<'a>(
    chain: &'a mut Vec<EntityStatement>,
    chain_jwts: &'a mut Vec<String>,
    current_entity_id: String,
    authority_hints: Vec<String>,
    ctx: &'a ChainResolutionContext<'a>,
    depth: usize,
) -> TrustChainResolutionFuture<'a, Result<TrustAnchor, FederationError>> {
    Box::pin(async move {
        if depth >= MAX_CHAIN_DEPTH {
            return Err(FederationError::ChainTooDeep);
        }
        ctx.enforce_authority_hints_budget(&current_entity_id, &authority_hints, depth)?;

        let start = Instant::now();

        for authority_id in authority_hints {
            ctx.record_authority_hint_attempt(&current_entity_id, &authority_id, depth)?;
            if ctx.authority_hint_revisits_path(chain, &current_entity_id, &authority_id, depth) {
                continue;
            }
            enforce_authority_hint_timeout(start, &current_entity_id, depth)?;
            let resolved = match ctx.anchor_map.get(authority_id.as_str()) {
                Some(anchor) => {
                    try_resolve_via_trust_anchor_with_jwts(
                        chain,
                        chain_jwts,
                        &current_entity_id,
                        &authority_id,
                        anchor,
                        ctx,
                        depth,
                    )
                    .await
                }
                None => {
                    try_resolve_via_intermediate_with_jwts(
                        chain,
                        chain_jwts,
                        &current_entity_id,
                        &authority_id,
                        ctx,
                        depth,
                    )
                    .await
                }
            };
            if let Some(anchor) = resolved {
                return Ok(anchor);
            }
        }

        Err(FederationError::ChainResolution(format!(
            "no cacheable JWS-backed path from {current_entity_id} to any trust anchor"
        )))
    })
}

pub(super) fn require_fetched_jws(
    surface: &'static str,
    entity_id: &str,
    jws: Option<String>,
) -> Result<String, FederationError> {
    jws.filter(|value| !value.trim().is_empty()).ok_or_else(|| {
        FederationError::Internal(format!(
            "{surface} fetch for {entity_id} did not retain compact JWS"
        ))
    })
}
