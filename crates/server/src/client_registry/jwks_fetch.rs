use super::jwks_circuit::circuit_allow_fetch_with_state;
use super::jwks_fetch_context::JwksFetchContext;
use super::jwks_fetch_memory::{probe_memory_cache, refresh_and_read_memory_cache};
use super::jwks_runtime_state::JwksRuntimeState;
use super::jwks_types::FetchedJwks;
use super::JwksRuntimePolicy;
use super::{maybe_log_event, metrics};

pub(super) fn fetch_jwks_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
) -> Option<FetchedJwks> {
    super::jwks_gc::maybe_run_gc_with_state(state, policy);

    let ctx = JwksFetchContext::new(state, policy, uri);
    // The process-local body cache is a positive, freshness-bound cache only.
    // Shared runtime state remains authoritative for fetch admission: once this
    // probe misses or the body is expired, Redis/in-memory circuit state decides
    // whether the process may perform network IO. There is intentionally no
    // stale-if-error path here.
    let memory = probe_memory_cache(&ctx);
    if let Some(hit) = memory.hit {
        return Some(hit);
    }

    if !circuit_allow_fetch_with_state(state, policy, uri) {
        record_circuit_fetch_refusal(&ctx);
        return None;
    }

    refresh_and_read_memory_cache(&ctx, memory.cached_etag, memory.cached_last_mod)
}

fn record_circuit_fetch_refusal(ctx: &JwksFetchContext<'_>) {
    metrics::record_jwks_http_event("circuit", ctx.uri_hash());
    metrics::record_jwks_http_failure_reason("circuit", ctx.uri_hash());
    maybe_log_event(ctx.policy, "circuit", ctx.uri, None);
}
