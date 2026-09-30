use super::super::jwks_cache_control::{CacheMetadata, ResponseTiming};
use super::super::jwks_circuit::{
    circuit_on_success_with_state, record_jwks_in_memory_runtime_state_failure,
};
use super::super::jwks_runtime_state::JwksRuntimeState;
use super::super::jwks_types::{CacheEntry, FetchedJwks, KidGuard};
use super::super::jwks_validators::JwksValidators;
use super::super::{maybe_log_event, metrics, JwksRuntimePolicy};
use std::sync::Arc;
use std::time::Instant;

pub(super) struct SuccessfulJwksFetch<'a> {
    pub(super) state: &'a JwksRuntimeState,
    pub(super) policy: &'a JwksRuntimePolicy,
    pub(super) uri: &'a str,
    pub(super) uri_hash: &'a str,
    pub(super) start: Instant,
    pub(super) jwks: &'a FetchedJwks,
    pub(super) guard: Arc<KidGuard>,
    pub(super) validators: JwksValidators,
    pub(super) effective_target: String,
    pub(super) metadata: CacheMetadata,
    pub(super) timing: ResponseTiming,
    pub(super) eligible_200: bool,
    pub(super) revalidated: bool,
}

pub(super) fn record_successful_fetch_with_state(fetch: SuccessfulJwksFetch<'_>) {
    let SuccessfulJwksFetch {
        state,
        policy,
        uri,
        uri_hash,
        start,
        jwks,
        guard,
        validators,
        effective_target,
        metadata,
        timing,
        eligible_200,
        revalidated,
    } = fetch;
    // The pre-shared-admission anchor is conservative for successful admission.
    // Metadata parsing, shared delay, and publication waiting cannot renew the
    // body-retention horizon or make this admission newer for capacity eviction.
    let fetched_at = guard.admitted_at;
    let freshness = metadata.freshness(timing, policy.cache_ttl_secs);
    let retain_until = freshness.retention_deadline(fetched_at, policy.cache_ttl_secs);
    let entry = retain_until
        .filter(|_| eligible_200 && metadata.permits_retention())
        .map(|retain_until| CacheEntry {
            validators,
            effective_target: Some(effective_target),
            metadata,
            freshness,
            retain_until,
            fetched_at,
            jwks: jwks.clone(),
            guard: guard.clone(),
        });
    match state.inner.cache.lock() {
        Ok(mut cache) => {
            if cache
                .publish(
                    uri,
                    guard,
                    entry,
                    Instant::now(),
                    policy.local_cache_max_entries,
                )
                .is_err()
            {
                record_jwks_in_memory_runtime_state_failure(
                    "memory_publication_clock",
                    uri,
                    "unavailable monotonic comparison",
                );
            }
        }
        Err(err) => {
            record_jwks_in_memory_runtime_state_failure("memory_publication_lock", uri, err)
        }
    }
    // Admission already completed for this call. Optional publication failure
    // does not revoke its owned result or create any future reuse permission.
    if revalidated {
        metrics::record_jwks_http_not_modified(policy, uri_hash, start.elapsed());
        maybe_log_event(policy, "304", uri, None);
    } else {
        metrics::record_jwks_http_success(policy, uri_hash, start.elapsed());
        maybe_log_event(policy, "200", uri, None);
    }
    circuit_on_success_with_state(state, policy, uri);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_registry::jwks_validators::DateContext;
    use reqwest::header::{HeaderMap, HeaderValue, CACHE_CONTROL};
    use std::time::Duration;

    #[test]
    fn delayed_publication_keeps_admission_retention_anchor() {
        // Controlled pure clock operands: shared admission succeeded at/before
        // the recorded anchor, then the publication path was delayed by600s.
        // This is not a host clock change or an actual600s supplier execution.
        let now = Instant::now();
        let anchor = now - Duration::from_secs(600);
        for (control, expected_lifetime, retained) in [
            ("no-cache", 60, false),
            ("max-age=500", 500, false),
            ("max-age=900", 900, true),
        ] {
            let state = JwksRuntimeState::default();
            let policy = JwksRuntimePolicy {
                cache_ttl_secs: 60,
                shared_state_max_age_secs: 3600,
                ..JwksRuntimePolicy::default()
            };
            let jwks: FetchedJwks =
                serde_json::from_str(r#"{"keys":[{"kty":"RSA","kid":"A","n":"AA","e":"AQAB"}]}"#)
                    .unwrap();
            let guard = Arc::new(KidGuard {
                kid_fps: crate::client_registry::jwks_validation::build_kid_fingerprints(&jwks),
                admitted_at: anchor,
                deadline: anchor + Duration::from_secs(3600),
            });
            let mut headers = HeaderMap::new();
            headers.insert(CACHE_CONTROL, HeaderValue::from_str(control).unwrap());
            let metadata = CacheMetadata::from_headers(&headers, DateContext::capture());
            record_successful_fetch_with_state(SuccessfulJwksFetch {
                state: &state,
                policy: &policy,
                uri: "https://example.com/jwks",
                uri_hash: "fixture",
                start: anchor,
                jwks: &jwks,
                guard: guard.clone(),
                validators: JwksValidators::default(),
                effective_target: "https://example.com/jwks".into(),
                metadata,
                timing: ResponseTiming {
                    request: anchor,
                    receipt: anchor,
                    receipt_utc: Some(0),
                },
                eligible_200: true,
                revalidated: false,
            });
            let cache = state.inner.cache.lock().unwrap();
            assert!(Arc::ptr_eq(
                &cache.guards["https://example.com/jwks"],
                &guard
            ));
            assert_eq!(cache.contains_key("https://example.com/jwks"), retained);
            if retained {
                let entry = cache.get("https://example.com/jwks").unwrap();
                assert_eq!(entry.fetched_at, anchor);
                assert_eq!(
                    entry.retain_until,
                    anchor + Duration::from_secs(expected_lifetime)
                );
                assert!(entry.freshness.reusable(now));
            }
            assert_eq!(
                jwks.keys[0].kid.as_deref(),
                Some("A"),
                "current owned body remains available"
            );
        }
    }
}
