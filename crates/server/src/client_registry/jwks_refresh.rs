use std::sync::{Arc, Mutex};

use super::jwks_circuit::circuit_on_failure_with_state;
use super::jwks_runtime_state::JwksRuntimeState;
use super::jwks_types::FetchedJwks;
use super::jwks_url::validate_jwks_fetch_url;
use super::jwks_validation::validate_fetched_jwks;
use super::{metrics, sha256_hex, JwksRuntimePolicy};
use tracing::warn;

mod background;
mod body;
mod cache_update;
mod client;
mod failure;
mod fetch_loop;
mod request;
mod retry;
mod validation;

#[cfg(test)]
pub(super) use background::spawn_jwks_refresh_once;
pub(super) use background::spawn_jwks_refresh_once_with_state;
#[cfg(test)]
pub(super) use body::decode_fetched_jwks_body;
use client::build_jwks_refresh_client;
use failure::record_jwks_refresh_internal_failure_with_state;
use fetch_loop::RefreshLoop;

pub(super) enum JwksRefreshOutcome {
    AdmittedBody(FetchedJwks),
    RevalidatedBody(FetchedJwks),
}

pub(super) fn refresh_jwks_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
) -> Option<JwksRefreshOutcome> {
    let uri_hash = &sha256_hex(uri.as_bytes())[0..8];
    let start = std::time::Instant::now();
    if let Err(err) = validate_jwks_fetch_url(policy, uri) {
        warn!(target: "jwks", uri_hash=%uri_hash, error=%err, "jwks_uri rejected before fetch");
        metrics::record_jwks_http_failure();
        metrics::record_jwks_http_failure_reason("url_policy", uri_hash);
        circuit_on_failure_with_state(state, policy, uri);
        return None;
    }
    let lock = fetch_lock_for_uri(state, policy, uri, uri_hash, start)?;
    let Ok(_guard) = lock.lock() else {
        record_jwks_refresh_internal_failure_with_state(
            state,
            policy,
            uri,
            uri_hash,
            "fetch_uri_lock_poisoned",
            start,
        );
        return None;
    };

    let captured = match state.inner.cache.lock() {
        Ok(mut cache) => cache.capture(uri, std::time::Instant::now()),
        Err(error) => {
            super::jwks_circuit::record_jwks_in_memory_runtime_state_failure(
                "candidate_capture_lock",
                uri,
                error,
            );
            Err(())
        }
    };
    let Ok((candidate, captured_guard)) = captured else {
        record_jwks_refresh_internal_failure_with_state(
            state,
            policy,
            uri,
            uri_hash,
            "candidate_capture",
            start,
        );
        return None;
    };
    let candidate = candidate.filter(|entry| validate_fetched_jwks(&entry.jwks).is_ok());

    let client = match build_jwks_refresh_client(policy, uri) {
        Ok(client) => client,
        Err(err) => {
            warn!(target: "jwks", uri_hash=%uri_hash, error=%err, "jwks refresh client build failed");
            record_jwks_refresh_internal_failure_with_state(
                state,
                policy,
                uri,
                uri_hash,
                "client_build",
                start,
            );
            return None;
        }
    };

    let (original_url, original_target) =
        prepare_original_target(&client, state, policy, uri, uri_hash, start)?;

    RefreshLoop {
        state,
        policy,
        uri,
        uri_hash,
        start,
        client,
        candidate,
        captured_guard,
        original_url,
        original_target,
        max_body: policy.max_body_bytes,
        retries: policy.http_retries,
    }
    .run()
}

fn prepare_original_target(
    client: &reqwest::blocking::Client,
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    start: std::time::Instant,
) -> Option<(url::Url, String)> {
    let original = match request::original_request(client, uri) {
        Ok(request) => request,
        Err(_) => {
            record_jwks_refresh_internal_failure_with_state(
                state,
                policy,
                uri,
                uri_hash,
                "request_build",
                start,
            );
            return None;
        }
    };
    let Some(original_target) = request::target_identity(original.url()) else {
        record_jwks_refresh_internal_failure_with_state(
            state,
            policy,
            uri,
            uri_hash,
            "request_target",
            start,
        );
        return None;
    };
    let original_url = original.url().clone();
    drop(original);
    Some((original_url, original_target))
}

fn fetch_lock_for_uri(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    start: std::time::Instant,
) -> Option<Arc<Mutex<()>>> {
    match state
        .inner
        .coordination
        .fetch_lock(policy.local_cache_max_entries, uri)
    {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => {
            record_jwks_refresh_internal_failure_with_state(
                state,
                policy,
                uri,
                uri_hash,
                "fetch_lock_capacity",
                start,
            );
            None
        }
        Err(err) => {
            record_jwks_refresh_internal_failure_with_state(
                state,
                policy,
                uri,
                uri_hash,
                "fetch_lock_poisoned",
                start,
            );
            warn!(target: "jwks", uri_hash=%uri_hash, error=%err, "jwks fetch lock unavailable");
            None
        }
    }
}
