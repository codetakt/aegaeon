use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::jwks_circuit::{
    circuit_on_failure_with_state, record_jwks_in_memory_runtime_state_failure,
};
use super::super::jwks_runtime_state::{JwksRuntimeState, RedisJwksRuntimeState};
use super::super::jwks_types::{FetchedJwks, KidGuard};
use super::super::jwks_validation::{
    build_kid_fingerprints, record_validation_failure, validate_fetched_jwks,
};
use super::super::{metrics, shared_kid_reuse_changed_with_state, JwksRuntimePolicy};
use super::body::decode_fetched_jwks_body_with_state;
use super::failure::record_jwks_refresh_internal_failure_with_state;
use tracing::warn;

pub(super) struct ValidatedRefreshedJwks {
    pub(super) jwks: FetchedJwks,
    pub(super) guard: Arc<KidGuard>,
}

pub(super) fn validate_refreshed_jwks_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    bytes: &[u8],
    start: Instant,
    captured_guard: Option<&KidGuard>,
) -> Option<ValidatedRefreshedJwks> {
    let jwks = decode_fetched_jwks_body_with_state(state, policy, uri, uri_hash, bytes, start)?;
    admit_jwks_with_state(state, policy, uri, uri_hash, jwks, start, captured_guard)
}

pub(super) fn admit_jwks_with_state(
    state: &JwksRuntimeState,
    policy: &JwksRuntimePolicy,
    uri: &str,
    uri_hash: &str,
    jwks: FetchedJwks,
    start: Instant,
    captured_guard: Option<&KidGuard>,
) -> Option<ValidatedRefreshedJwks> {
    if let Err(err) = validate_fetched_jwks(&jwks) {
        record_validation_failure(uri, &err, "http_fetch", Some(uri_hash));
        circuit_on_failure_with_state(state, policy, uri);
        return None;
    }
    let kid_fps = build_kid_fingerprints(&jwks);
    let local_comparison = match state.inner.cache.lock() {
        Ok(mut cache) => {
            let now = Instant::now();
            cache.prune(now).map(|()| {
                !policy.allow_kid_reuse
                    && (captured_guard.is_some_and(|old| old.conflicts(&kid_fps))
                        || cache
                            .guards
                            .get(uri)
                            .is_some_and(|old| old.conflicts(&kid_fps)))
            })
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("kid_memory_state_lock", uri, err);
            Err(())
        }
    };
    match local_comparison {
        Ok(false) => {}
        Ok(true) => {
            metrics::record_jwks_kid_reuse_violation();
            circuit_on_failure_with_state(state, policy, uri);
            return None;
        }
        Err(()) => {
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
    // Required security horizon begins before this call's shared admission.
    let admitted_at = Instant::now();
    let deadline = RedisJwksRuntimeState::ttl_i64(policy)
        .ok()
        .and_then(|seconds| u64::try_from(seconds).ok())
        .and_then(|seconds| admitted_at.checked_add(Duration::from_secs(seconds)));
    let Some(deadline) = deadline else {
        record_jwks_refresh_internal_failure_with_state(
            state,
            policy,
            uri,
            uri_hash,
            "kid_retention",
            start,
        );
        return None;
    };
    match shared_kid_reuse_changed_with_state(state, policy, uri, &kid_fps) {
        Ok(true) => {
            metrics::record_jwks_kid_reuse_violation();
            circuit_on_failure_with_state(state, policy, uri);
            None
        }
        Ok(false) => {
            #[cfg(test)]
            tracing::debug!(target: "jwks_admission", uri_hash=%uri_hash, "local/shared admission complete before optional publication");
            Some(ValidatedRefreshedJwks {
                jwks,
                guard: Arc::new(KidGuard {
                    kid_fps,
                    admitted_at,
                    deadline,
                }),
            })
        }
        Err(err) => {
            warn!(target: "jwks", uri_hash=%uri_hash, error=%err, "failed to verify shared JWKS kid fingerprint state");
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
