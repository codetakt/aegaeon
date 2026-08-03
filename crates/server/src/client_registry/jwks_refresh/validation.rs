use std::collections::HashMap;

use super::super::jwks_circuit::{
    circuit_on_failure_with_state, record_jwks_in_memory_runtime_state_failure,
};
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::jwks_types::FetchedJwks;
use super::super::jwks_validation::{
    build_kid_fingerprints, kid_reuse_changed, record_validation_failure, validate_fetched_jwks,
};
use super::super::{metrics, shared_kid_reuse_changed_with_state, JwksRuntimePolicy};
use super::body::decode_fetched_jwks_body_with_state;
use super::failure::record_jwks_refresh_internal_failure_with_state;
use tracing::warn;

pub(super) struct ValidatedRefreshedJwks {
    pub(super) jwks: FetchedJwks,
    pub(super) kid_fps: HashMap<String, String>,
}

pub(super) fn validate_refreshed_jwks_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    bytes: &[u8],
    start: std::time::Instant,
) -> Option<ValidatedRefreshedJwks> {
    let jwks = decode_fetched_jwks_body_with_state(state, policy, uri, uri_hash, bytes, start)?;
    if let Err(err) = validate_fetched_jwks(&jwks) {
        record_validation_failure(uri, &err, "http_fetch", Some(uri_hash));
        circuit_on_failure_with_state(state, policy, uri);
        return None;
    }

    let kid_fps = build_kid_fingerprints(&jwks);
    match state.inner.cache.lock() {
        Ok(cache) => {
            if let Some(prev) = cache.get(uri) {
                if kid_reuse_changed(prev, &kid_fps) && !policy.allow_kid_reuse {
                    metrics::record_jwks_kid_reuse_violation();
                    circuit_on_failure_with_state(state, policy, uri);
                    return None;
                }
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("kid_memory_state_lock", uri, err);
            record_jwks_refresh_internal_failure_with_state(
                state,
                policy,
                uri,
                uri_hash,
                "kid_memory_state",
                start,
            );
            return None;
        }
    }
    match shared_kid_reuse_changed_with_state(state, policy, uri, &kid_fps) {
        Ok(true) => {
            metrics::record_jwks_kid_reuse_violation();
            circuit_on_failure_with_state(state, policy, uri);
            None
        }
        Ok(false) => Some(ValidatedRefreshedJwks { jwks, kid_fps }),
        Err(err) => {
            warn!(
                target: "jwks",
                uri_hash = %uri_hash,
                error = %err,
                "failed to verify shared JWKS kid fingerprint state"
            );
            record_jwks_refresh_internal_failure_with_state(
                state,
                policy,
                uri,
                uri_hash,
                "kid_shared_state",
                start,
            );
            None
        }
    }
}
