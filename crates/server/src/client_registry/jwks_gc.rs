use super::jwks_circuit::record_jwks_in_memory_runtime_state_failure;
use super::jwks_runtime_state::JwksRuntimeState;
use super::jwks_types::CacheEntry;
use super::JwksRuntimePolicy;
use std::collections::HashMap;

pub(super) fn maybe_run_gc_with_state(state: &JwksRuntimeState, policy: &JwksRuntimePolicy) {
    let now = std::time::Instant::now();
    match state.inner.last_gc.lock() {
        Ok(mut last) => {
            let should = match *last {
                None => true,
                Some(t) => now.duration_since(t).as_secs() >= policy.cache_gc_interval_secs,
            };
            if should {
                run_gc_inner_with_state(state, policy);
                *last = Some(now);
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("memory_gc_timer_lock", "gc", err);
        }
    }
}

fn run_gc_inner_with_state(state: &JwksRuntimeState, policy: &JwksRuntimePolicy) {
    let ttl_default = policy.cache_ttl_secs;
    let now = std::time::Instant::now();
    match state.inner.cache.lock() {
        Ok(mut cache) => {
            cache.retain(|_, entry| {
                entry.expires_at.map_or_else(
                    || entry.fetched_at.elapsed().as_secs() <= ttl_default,
                    |expires_at| now < expires_at,
                )
            });
            prune_cache_to_capacity(&mut cache, policy.local_cache_max_entries);
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("memory_gc_cache_lock", "gc", err);
        }
    }
    if let Err(err) = state
        .inner
        .coordination
        .prune_idle_fetch_locks(policy.local_cache_max_entries)
    {
        record_jwks_in_memory_runtime_state_failure("memory_gc_fetch_lock", "gc", err);
    }
}

pub(super) fn prune_cache_to_capacity(cache: &mut HashMap<String, CacheEntry>, max_entries: usize) {
    let max_entries = max_entries.max(1);
    while cache.len() > max_entries {
        let Some(evict_key) = oldest_cache_entry_key(cache) else {
            return;
        };
        cache.remove(&evict_key);
    }
}

fn oldest_cache_entry_key(cache: &HashMap<String, CacheEntry>) -> Option<String> {
    cache
        .iter()
        .min_by(|(left_key, left), (right_key, right)| {
            left.fetched_at
                .cmp(&right.fetched_at)
                .then_with(|| left_key.cmp(right_key))
        })
        .map(|(key, _)| key.clone())
}
