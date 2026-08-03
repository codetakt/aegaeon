use super::jwks_cache_control::instant_after_secs;
use super::jwks_circuit::record_jwks_in_memory_runtime_state_failure;
use super::jwks_fetch_context::{JwksFetchContext, MemoryCacheProbe};
use super::jwks_refresh::{refresh_jwks_with_state, spawn_jwks_refresh_once_with_state};
use super::jwks_types::{CacheEntry, FetchedJwks};
use super::jwks_validation::{record_validation_failure, validate_fetched_jwks};
use super::metrics;
use tracing::debug;

pub(super) fn probe_memory_cache(ctx: &JwksFetchContext<'_>) -> MemoryCacheProbe {
    let mut probe = MemoryCacheProbe::default();
    match ctx.state.inner.cache.lock() {
        Ok(cache) => {
            if let Some(entry) = cache.get(ctx.uri) {
                if memory_cache_entry_valid(entry, ctx) {
                    match validate_fetched_jwks(&entry.jwks) {
                        Ok(()) => {
                            spawn_refresh_if_near_expiry(ctx, entry);
                            metrics::record_jwks_cache_hit_memory();
                            debug!(target: "jwks", uri=%ctx.uri, "memory cache hit");
                            probe.hit = Some(entry.jwks.clone());
                            return probe;
                        }
                        Err(err) => {
                            record_validation_failure(ctx.uri, &err, "memory_cache", None);
                        }
                    }
                }
                probe.cached_etag.clone_from(&entry.etag);
                probe.cached_last_mod.clone_from(&entry.last_modified);
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("memory_probe_lock", ctx.uri, err);
        }
    }
    probe
}

fn memory_cache_entry_valid(entry: &CacheEntry, ctx: &JwksFetchContext<'_>) -> bool {
    entry.expires_at.map_or_else(
        || entry.fetched_at.elapsed().as_secs() <= ctx.ttl_default,
        |exp| ctx.now < exp,
    )
}

fn spawn_refresh_if_near_expiry(ctx: &JwksFetchContext<'_>, entry: &CacheEntry) {
    let near_expiry = entry.expires_at.is_some_and(|exp| {
        instant_after_secs(ctx.now, ctx.skew_secs).is_none_or(|threshold| exp <= threshold)
    });
    if near_expiry {
        spawn_jwks_refresh_once_with_state(
            ctx.state,
            ctx.policy.clone(),
            ctx.uri,
            entry.etag.clone(),
            entry.last_modified.clone(),
        );
    }
}

pub(super) fn refresh_and_read_memory_cache(
    ctx: &JwksFetchContext<'_>,
    cached_etag: Option<String>,
    cached_last_mod: Option<String>,
) -> Option<FetchedJwks> {
    let _ = refresh_jwks_with_state(ctx.state, ctx.policy, ctx.uri, cached_etag, cached_last_mod);
    match ctx.state.inner.cache.lock() {
        Ok(cache) => {
            if let Some(entry) = cache.get(ctx.uri) {
                match validate_fetched_jwks(&entry.jwks) {
                    Ok(()) => return Some(entry.jwks.clone()),
                    Err(err) => {
                        record_validation_failure(ctx.uri, &err, "post_fetch_cache", None);
                    }
                }
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("post_fetch_cache_lock", ctx.uri, err);
        }
    }
    None
}
