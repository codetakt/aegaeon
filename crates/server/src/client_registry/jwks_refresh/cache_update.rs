use std::collections::HashMap;

use super::super::jwks_cache_control::{instant_after_secs, parse_cache_control};
use super::super::jwks_circuit::{
    circuit_on_success_with_state, record_jwks_in_memory_runtime_state_failure,
};
use super::super::jwks_gc::prune_cache_to_capacity;
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::jwks_types::{CacheEntry, FetchedJwks};
use super::super::{maybe_log_event, metrics, JwksRuntimePolicy};

pub(super) struct SuccessfulJwksFetch<'a> {
    pub(super) state: &'a JwksRuntimeState,
    pub(super) policy: &'a JwksRuntimePolicy,
    pub(super) uri: &'a str,
    pub(super) uri_hash: &'a str,
    pub(super) start: std::time::Instant,
    pub(super) headers: &'a reqwest::header::HeaderMap,
    pub(super) jwks: &'a FetchedJwks,
    pub(super) kid_fingerprints: HashMap<String, String>,
}

pub(super) fn record_not_modified_response_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    headers: &reqwest::header::HeaderMap,
    start: std::time::Instant,
) {
    let cc = parse_cache_control(headers);
    let fetched_at = std::time::Instant::now();
    let expires_at = cc.and_then(|s| instant_after_secs(fetched_at, s));
    match state.inner.cache.lock() {
        Ok(mut cache) => {
            if let Some(entry) = cache.get_mut(uri) {
                entry.fetched_at = fetched_at;
                entry.expires_at = expires_at.or(entry.expires_at);
                entry.etag = headers
                    .get(reqwest::header::ETAG)
                    .and_then(|value| value.to_str().ok())
                    .map(std::string::ToString::to_string)
                    .or(entry.etag.clone());
                entry.last_modified = headers
                    .get(reqwest::header::LAST_MODIFIED)
                    .and_then(|value| value.to_str().ok())
                    .map(std::string::ToString::to_string)
                    .or(entry.last_modified.clone());
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("memory_update_304_lock", uri, err);
        }
    }
    metrics::record_jwks_http_not_modified(policy, uri_hash, start.elapsed());
    maybe_log_event(policy, "304", uri, None);
    circuit_on_success_with_state(state, policy, uri);
}

pub(super) fn record_successful_fetch_with_state(fetch: SuccessfulJwksFetch<'_>) {
    let SuccessfulJwksFetch {
        state,
        policy,
        uri,
        uri_hash,
        start,
        headers,
        jwks,
        kid_fingerprints,
    } = fetch;

    let cc = parse_cache_control(headers);
    let fetched_at = std::time::Instant::now();
    let expires_at = cc.and_then(|s| instant_after_secs(fetched_at, s));
    let etag_new = headers
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(std::string::ToString::to_string);
    let last_mod_new = headers
        .get(reqwest::header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .map(std::string::ToString::to_string);
    match state.inner.cache.lock() {
        Ok(mut cache) => {
            cache.insert(
                uri.to_string(),
                CacheEntry {
                    etag: etag_new.clone(),
                    expires_at,
                    fetched_at,
                    jwks: jwks.clone(),
                    kid_fps: kid_fingerprints.clone(),
                    last_modified: last_mod_new.clone(),
                },
            );
            prune_cache_to_capacity(&mut cache, policy.local_cache_max_entries);
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("memory_store_fetch_lock", uri, err);
        }
    }
    metrics::record_jwks_http_success(policy, uri_hash, start.elapsed());
    maybe_log_event(policy, "200", uri, None);
    circuit_on_success_with_state(state, policy, uri);
}
