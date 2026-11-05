//! Native remote-key acquisition. SQL owns permission; memory owns optional bodies.
use super::jwks_cache_control::{CacheMetadata, Freshness};
use super::jwks_runtime_state::postgres::{AdmittedKeys, Completion, PostgresJwksState};
use super::jwks_types::FetchedJwks;
use super::jwks_validators::JwksValidators;
use super::JwksRuntimePolicy;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

mod background;
mod cache;
#[cfg(test)]
mod tests;
mod transport;

pub(super) struct NativeJwksRuntime {
    state: PostgresJwksState,
    policy: JwksRuntimePolicy,
    client: reqwest::Client,
    #[cfg(test)]
    loopback_client: reqwest::Client,
    cache: Mutex<cache::BodyCache>,
    fetch_slots: tokio::sync::Semaphore,
    background: Mutex<tokio::task::JoinSet<()>>,
    background_uris: Arc<Mutex<std::collections::HashSet<String>>>,
}

pub(super) struct Body {
    pub(super) jwks: FetchedJwks,
    admission: AdmittedKeys,
    charge: usize,
}

struct Entry {
    body: Arc<Body>,
    metadata: CacheMetadata,
    freshness: Freshness,
    validators: JwksValidators,
    target: String,
    admitted_at: Instant,
    retain_until: Instant,
    charge: usize,
    header_charge: usize,
}

impl NativeJwksRuntime {
    pub(super) fn new(
        pool: sqlx::PgPool,
        namespace: &crate::config::RuntimeStateNamespace,
        policy: JwksRuntimePolicy,
    ) -> Result<Self, String> {
        Ok(Self {
            state: PostgresJwksState::new(pool, namespace),
            client: transport::client(&policy, false)?,
            #[cfg(test)]
            loopback_client: transport::client(&policy, true)?,
            policy,
            cache: Mutex::new(cache::BodyCache::default()),
            fetch_slots: tokio::sync::Semaphore::new(32),
            background: Mutex::new(tokio::task::JoinSet::new()),
            background_uris: Arc::new(Mutex::new(std::collections::HashSet::new())),
        })
    }

    fn cache_guard(&self) -> std::sync::MutexGuard<'_, cache::BodyCache> {
        self.cache.lock().unwrap_or_else(|poisoned| {
            let mut cache = poisoned.into_inner();
            *cache = cache::BodyCache::default();
            self.cache.clear_poison();
            tracing::warn!(target:"jwks", "discarded poisoned optional JWKS body cache");
            cache
        })
    }

    pub(super) async fn cleanup(&self) -> Result<(), String> {
        self.cache_guard().prune(Instant::now());
        self.state.cleanup().await
    }

    pub(super) async fn fetch(self: &Arc<Self>, uri: &str) -> Result<Option<Arc<Body>>, String> {
        transport::validate_target(&self.policy, uri, false)?;
        let now = Instant::now();
        let candidate = self.cache_guard().capture(uri, now);
        if let Some(entry) = &candidate {
            if entry.freshness.reusable(now)
                && self
                    .state
                    .current_body(uri, &entry.body.admission.body_digest())
                    .await
                    .inspect_err(|_| {
                        super::metrics::record_jwks_shared_runtime_state_failure(
                            "native_cached_body",
                            &super::sha256_hex(uri.as_bytes())[..8],
                        );
                    })?
            {
                // The authority lookup can wait. Never extend HTTP/body freshness.
                let now = Instant::now();
                if now < entry.retain_until && entry.freshness.reusable(now) {
                    if entry
                        .freshness
                        .remaining(now)
                        .is_some_and(|r| r <= Duration::from_secs(self.policy.refresh_skew_secs))
                    {
                        self.schedule_refresh(uri);
                    }
                    super::metrics::record_jwks_cache_hit_memory();
                    return Ok(Some(entry.body.clone()));
                }
            }
        }
        self.refresh_candidate(uri, candidate).await
    }

    async fn refresh_candidate(
        &self,
        uri: &str,
        candidate: Option<Arc<Entry>>,
    ) -> Result<Option<Arc<Body>>, String> {
        let start = Instant::now();
        let hash = super::sha256_hex(uri.as_bytes());
        let uri_hash = &hash[..8];
        // Capacity refusal is local to this acquisition and creates no SQL owner.
        let _slot = self.fetch_slots.try_acquire().map_err(|_| {
            super::metrics::record_jwks_http_failure_reason("capacity", uri_hash);
            unavailable()
        })?;
        let Some(permit) = self
            .state
            .acquire(uri, &self.policy)
            .await
            .inspect_err(|_| {
                super::metrics::record_jwks_shared_runtime_state_failure(
                    "native_acquire",
                    uri_hash,
                );
            })?
        else {
            super::metrics::record_jwks_http_event("busy_or_open", uri_hash);
            return Ok(None);
        };
        let budget = permit
            .remaining()
            .and_then(|d| d.checked_sub(Duration::from_secs(5)));
        let result = match budget {
            Some(budget) => tokio::time::timeout(budget, transport::fetch(self, uri, candidate))
                .await
                .map_err(|_| unavailable())
                .and_then(|r| r),
            None => Err(unavailable()),
        };
        let fetched = match result {
            Ok(fetched) => fetched,
            Err(error) => {
                super::metrics::record_jwks_http_error(
                    &self.policy,
                    uri_hash,
                    "native_acquisition",
                    start.elapsed(),
                );
                self.state.finish(&permit, None).await.inspect_err(|_| {
                    super::metrics::record_jwks_shared_runtime_state_failure(
                        "native_failure",
                        uri_hash,
                    );
                })?;
                return Err(error);
            }
        };
        // This anchor precedes SQL admission. Publication cannot renew retention.
        let admitted_at = Instant::now();
        let completion = self
            .state
            .finish(&permit, Some(&fetched.body.admission))
            .await
            .inspect_err(|_| {
                super::metrics::record_jwks_shared_runtime_state_failure("native_finish", uri_hash);
            })?;
        match completion {
            Completion::Admitted => {}
            Completion::ChangedKey => {
                super::metrics::record_jwks_kid_reuse_violation();
                super::metrics::record_jwks_http_failure_reason("kid_reuse", uri_hash);
                return Ok(None);
            }
            Completion::Failed | Completion::Capacity => {
                super::metrics::record_jwks_http_failure_reason("binding_capacity", uri_hash);
                return Ok(None);
            }
        }
        if fetched.revalidated {
            super::metrics::record_jwks_http_not_modified(&self.policy, uri_hash, start.elapsed());
        } else {
            super::metrics::record_jwks_http_success(&self.policy, uri_hash, start.elapsed());
        }
        Ok(Some(self.publish(uri, fetched, admitted_at)))
    }

    fn publish(&self, uri: &str, fetched: transport::Fetched, admitted_at: Instant) -> Arc<Body> {
        let body = fetched.body.clone();
        let freshness = fetched
            .metadata
            .freshness(fetched.timing, self.policy.cache_ttl_secs);
        let entry = freshness
            .retention_deadline(admitted_at, self.policy.cache_ttl_secs)
            .filter(|_| fetched.eligible && fetched.metadata.permits_retention())
            .map(|retain_until| {
                Arc::new(Entry {
                    header_charge: fetched.header_charge,
                    charge: body
                        .charge
                        .saturating_add(fetched.header_charge)
                        .saturating_add(uri.len())
                        .saturating_add(1024),
                    body: body.clone(),
                    metadata: fetched.metadata,
                    freshness,
                    validators: fetched.validators,
                    target: fetched.target,
                    admitted_at,
                    retain_until,
                })
            });
        // Optional cache failure never manufactures permission or revokes an owned result.
        self.cache_guard().publish(
            uri,
            entry,
            Instant::now(),
            self.policy.local_cache_max_entries,
        );
        body
    }
}

fn unavailable() -> String {
    "JWKS acquisition unavailable or invalid".into()
}
