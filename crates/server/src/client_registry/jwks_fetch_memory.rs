use super::jwks_circuit::record_jwks_in_memory_runtime_state_failure;
use super::jwks_fetch_context::{JwksFetchContext, MemoryCacheProbe};
use super::jwks_refresh::{
    refresh_jwks_with_state, spawn_jwks_refresh_once_with_state, JwksRefreshOutcome,
};
use super::jwks_types::FetchedJwks;
use super::jwks_validation::{record_validation_failure, validate_fetched_jwks};
use super::metrics;
use std::time::{Duration, Instant};
use tracing::debug;

pub(super) fn probe_memory_cache(ctx: &JwksFetchContext<'_>) -> MemoryCacheProbe {
    let mut probe = MemoryCacheProbe::default();
    // Sample only after acquiring the local mutex: ctx construction/lock waits
    // cannot disappear from age or from the guard's security horizon.
    let (hit, near) = match ctx.state.inner.cache.lock() {
        Ok(cache) => {
            let now = Instant::now();
            if let Some(entry) = cache.reusable(ctx.uri, now) {
                let skew = Duration::from_secs(ctx.skew_secs);
                let near = entry.freshness.remaining(now).is_some_and(|r| r <= skew)
                    || entry
                        .guard
                        .deadline
                        .checked_duration_since(now)
                        .is_none_or(|r| r <= skew);
                (Some(entry.jwks.clone()), near)
            } else {
                (None, false)
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("memory_probe_lock", ctx.uri, err);
            probe.authoritative_failure = true;
            return probe;
        }
    };
    if let Some(hit) = hit {
        if let Err(err) = validate_fetched_jwks(&hit) {
            record_validation_failure(ctx.uri, &err, "memory_cache", None);
            return probe;
        }
        // No local-state lock is held during coordination/spawn.
        if near {
            spawn_jwks_refresh_once_with_state(ctx.state, ctx.policy.clone(), ctx.uri);
        }
        metrics::record_jwks_cache_hit_memory();
        debug!(target: "jwks", uri=%ctx.uri, "memory cache hit");
        probe.hit = Some(hit);
    }
    probe
}

pub(super) fn refresh_and_read_memory_cache(ctx: &JwksFetchContext<'_>) -> Option<FetchedJwks> {
    match refresh_jwks_with_state(ctx.state, ctx.policy, ctx.uri) {
        Some(
            JwksRefreshOutcome::AdmittedBody(jwks) | JwksRefreshOutcome::RevalidatedBody(jwks),
        ) => return Some(jwks),
        None => {}
    }
    let body = match ctx.state.inner.cache.lock() {
        Ok(cache) => cache
            .reusable(ctx.uri, Instant::now())
            .map(|entry| entry.jwks.clone()),
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("post_fetch_cache_lock", ctx.uri, err);
            None
        }
    }?;
    match validate_fetched_jwks(&body) {
        Ok(()) => Some(body),
        Err(err) => {
            record_validation_failure(ctx.uri, &err, "post_fetch_cache", None);
            None
        }
    }
}
