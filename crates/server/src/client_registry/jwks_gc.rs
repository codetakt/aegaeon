use super::jwks_circuit::record_jwks_in_memory_runtime_state_failure;
use super::jwks_runtime_state::{JwksLocalCache, JwksRuntimeState};
use super::JwksRuntimePolicy;

pub(super) fn maybe_run_gc_with_state(state: &JwksRuntimeState, policy: &JwksRuntimePolicy) {
    match state.inner.last_gc.lock() {
        Ok(mut last) => {
            let now = std::time::Instant::now();
            let should = last.is_none_or(|t| {
                now.checked_duration_since(t)
                    .is_some_and(|elapsed| elapsed.as_secs() >= policy.cache_gc_interval_secs)
            });
            if should {
                run_gc_inner_with_state(state, policy);
                *last = Some(now);
            }
        }
        Err(err) => record_jwks_in_memory_runtime_state_failure("memory_gc_timer_lock", "gc", err),
    }
}

fn run_gc_inner_with_state(state: &JwksRuntimeState, policy: &JwksRuntimePolicy) {
    match state.inner.cache.lock() {
        Ok(mut cache) => {
            let now = std::time::Instant::now();
            if cache.prune(now).is_ok() {
                prune_cache_to_capacity(&mut cache, policy.local_cache_max_entries);
            } else {
                record_jwks_in_memory_runtime_state_failure(
                    "memory_gc_clock",
                    "gc",
                    "unavailable monotonic comparison",
                );
            }
        }
        Err(err) => record_jwks_in_memory_runtime_state_failure("memory_gc_cache_lock", "gc", err),
    }
    if let Err(err) = state
        .inner
        .coordination
        .prune_idle_fetch_locks(policy.local_cache_max_entries)
    {
        record_jwks_in_memory_runtime_state_failure("memory_gc_fetch_lock", "gc", err);
    }
}

pub(super) fn prune_cache_to_capacity(cache: &mut JwksLocalCache, max_entries: usize) {
    cache.prune_to_capacity(max_entries);
}
