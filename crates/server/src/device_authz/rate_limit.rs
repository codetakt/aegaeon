#[cfg(test)]
use super::write_lock;
use crate::config::{require_shared_runtime_store_url, ConfigError, RuntimeStateNamespace};
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(test)]
use std::sync::RwLock;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

mod redis_backend;

use redis_backend::RedisVerificationRateLimiter;

/// Per-IP rate limiter for user code lookups on the verification endpoint.
pub struct VerificationRateLimiter {
    backend: VerificationRateLimiterBackend,
    max_attempts: u32,
    window: Duration,
}

enum VerificationRateLimiterBackend {
    #[cfg(test)]
    InMemory {
        attempts: RwLock<HashMap<String, (u32, Instant)>>,
    },
    Redis(RedisVerificationRateLimiter),
}

impl VerificationRateLimiter {
    #[cfg(test)]
    fn new_process_local() -> Self {
        Self {
            backend: VerificationRateLimiterBackend::InMemory {
                attempts: RwLock::new(HashMap::new()),
            },
            max_attempts: 10,
            window: Duration::from_secs(60),
        }
    }

    /// Create a process-local verification rate limiter for tests.
    ///
    /// Production code should use [`Self::try_from_shared_store_env`] so shared runtime state is
    /// required.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local()
    }

    /// Build a rate limiter from a specific Redis URL env var.
    pub fn try_from_shared_store_env(
        specific_url_key: &str,
        flow: &'static str,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let url = require_shared_runtime_store_url("verification rate limiter", specific_url_key)?;
        let redis_namespace = runtime_state_namespace.flow_namespace("rate-limit", flow);
        let backend = RedisVerificationRateLimiter::new(url.as_str(), redis_namespace.clone())
            .map_err(|err| ConfigError::InvalidValue {
                key: url.env_key().to_string(),
                value: "[redacted]".to_string(),
                reason: err.to_string(),
            })?;
        tracing::info!(
            flow,
            namespace = %redis_namespace,
            "verification rate limiter backend: redis"
        );
        Ok(Self {
            backend: VerificationRateLimiterBackend::Redis(backend),
            max_attempts: 10,
            window: Duration::from_secs(60),
        })
    }

    /// Check if the given key is admitted, reporting backend failures.
    pub fn try_check(&self, key: &str) -> Result<bool, String> {
        self.try_check_all(std::iter::once(key))
    }

    /// Check if the given key is admitted on the blocking worker pool.
    pub async fn try_check_async(self: Arc<Self>, key: String) -> Result<bool, String> {
        tokio::task::spawn_blocking(move || self.try_check(&key))
            .await
            .map_err(|err| format!("verification rate limiter worker failed: {err}"))?
    }

    /// Admit one attempt across all supplied buckets, reporting backend failures.
    pub fn try_check_all<'a>(
        &self,
        keys: impl IntoIterator<Item = &'a str>,
    ) -> Result<bool, String> {
        let keys = distinct_rate_limit_keys(keys);
        if keys.is_empty() {
            return Ok(true);
        }

        match &self.backend {
            #[cfg(test)]
            VerificationRateLimiterBackend::InMemory { attempts } => {
                Ok(self.check_all_in_memory(attempts, &keys))
            }
            VerificationRateLimiterBackend::Redis(store) => store
                .check_all(&keys, self.max_attempts, self.window)
                .map_err(|err| {
                    let message = err.to_string();
                    tracing::error!(
                        error = %err,
                        namespace = %store.namespace,
                        "verification rate limiter backend unavailable"
                    );
                    message
                }),
        }
    }

    /// Admit one attempt across all supplied buckets on the blocking worker pool.
    pub async fn try_check_all_async(self: Arc<Self>, keys: Vec<String>) -> Result<bool, String> {
        tokio::task::spawn_blocking(move || self.try_check_all(keys.iter().map(String::as_str)))
            .await
            .map_err(|err| format!("verification rate limiter worker failed: {err}"))?
    }

    #[cfg(test)]
    fn check_all_in_memory(
        &self,
        attempts: &RwLock<HashMap<String, (u32, Instant)>>,
        keys: &[&str],
    ) -> bool {
        let now = Instant::now();
        let Ok(mut map) = write_lock(attempts, "rate_limit_check_all") else {
            return false;
        };
        let next_entries = keys
            .iter()
            .map(|key| {
                let next = match map.get(*key).copied() {
                    Some((count, since)) if now.duration_since(since) <= self.window => {
                        (count.saturating_add(1), since)
                    }
                    _ => (1, now),
                };
                (*key, next)
            })
            .collect::<Vec<_>>();

        if next_entries
            .iter()
            .any(|(_, (count, _))| *count > self.max_attempts)
        {
            return false;
        }

        next_entries.into_iter().for_each(|(key, entry)| {
            map.insert(key.to_string(), entry);
        });
        true
    }

    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        match &self.backend {
            #[cfg(test)]
            VerificationRateLimiterBackend::InMemory { attempts } => {
                let now = Instant::now();
                let mut map = write_lock(attempts, "rate_limit_cleanup")?;
                map.retain(|_, (_, since)| now.duration_since(*since) <= self.window);
                Ok(())
            }
            VerificationRateLimiterBackend::Redis(_) => Ok(()),
        }
    }

    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test rate limiter cleanup should succeed");
    }
}

fn distinct_rate_limit_keys<'a>(keys: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let mut keys = keys.into_iter().collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), String>;

    fn check(limiter: &VerificationRateLimiter, key: &str) -> Result<bool, String> {
        limiter
            .try_check(key)
            .map_err(|err| format!("rate limiter check should not fail: {err}"))
    }

    fn check_all<'a>(
        limiter: &VerificationRateLimiter,
        keys: impl IntoIterator<Item = &'a str>,
    ) -> Result<bool, String> {
        limiter
            .try_check_all(keys)
            .map_err(|err| format!("rate limiter composite check should not fail: {err}"))
    }

    #[test]
    fn rate_limiter_allows_within_limit() -> TestResult {
        let limiter = VerificationRateLimiter::new_process_local_for_tests();
        for _ in 0..10 {
            assert!(check(&limiter, "1.2.3.4")?);
        }
        assert!(!check(&limiter, "1.2.3.4")?);
        Ok(())
    }

    #[test]
    fn rate_limiter_independent_keys() -> TestResult {
        let limiter = VerificationRateLimiter::new_process_local_for_tests();
        for _ in 0..10 {
            let _ = check(&limiter, "1.2.3.4")?;
        }
        assert!(check(&limiter, "5.6.7.8")?);
        Ok(())
    }

    #[test]
    fn rate_limiter_counter_saturates_after_limit() -> TestResult {
        let limiter = VerificationRateLimiter {
            backend: VerificationRateLimiterBackend::InMemory {
                attempts: RwLock::new(HashMap::new()),
            },
            max_attempts: 1,
            window: Duration::from_secs(60),
        };
        if let VerificationRateLimiterBackend::InMemory { attempts } = &limiter.backend {
            let mut attempts = write_lock(attempts, "test_rate_limiter_counter_saturates")
                .map_err(|err| format!("rate limiter write lock: {err}"))?;
            attempts.insert("1.2.3.4".to_string(), (u32::MAX, Instant::now()));
        }

        assert!(!check(&limiter, "1.2.3.4")?);
        if let VerificationRateLimiterBackend::InMemory { attempts } = &limiter.backend {
            let attempts = attempts
                .read()
                .map_err(|err| format!("rate limiter read lock: {err}"))?;
            assert_eq!(attempts.get("1.2.3.4").map(|entry| entry.0), Some(u32::MAX));
        }
        Ok(())
    }

    #[test]
    fn rate_limiter_check_all_is_all_or_nothing() -> TestResult {
        let limiter = VerificationRateLimiter {
            backend: VerificationRateLimiterBackend::InMemory {
                attempts: RwLock::new(HashMap::new()),
            },
            max_attempts: 1,
            window: Duration::from_secs(60),
        };

        assert!(check(&limiter, "ip")?);
        assert!(
            !check_all(&limiter, ["principal", "ip"])?,
            "composite admission must fail when any bucket is exhausted"
        );
        assert!(
            check(&limiter, "principal")?,
            "failed composite admission must not consume other buckets"
        );
        assert!(!check(&limiter, "principal")?);
        Ok(())
    }

    #[test]
    #[ignore = "requires AEGAEON_TEST_REDIS_URL"]
    fn redis_rate_limiter_shares_buckets_and_preserves_all_or_nothing() -> TestResult {
        let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
        let Ok(url) = std::env::var(redis_url_env) else {
            return Ok(());
        };
        let namespace = format!(
            "rate-limit-test-{}",
            aegaeon_crypto::rand::random_base64url(8)
        );
        let limiter_a = VerificationRateLimiter {
            backend: VerificationRateLimiterBackend::Redis(
                RedisVerificationRateLimiter::new(url.trim(), Arc::<str>::from(namespace.clone()))
                    .map_err(|err| format!("redis rate limiter: {err}"))?,
            ),
            max_attempts: 1,
            window: Duration::from_secs(60),
        };
        let limiter_b = VerificationRateLimiter {
            backend: VerificationRateLimiterBackend::Redis(
                RedisVerificationRateLimiter::new(url.trim(), Arc::<str>::from(namespace))
                    .map_err(|err| format!("redis rate limiter: {err}"))?,
            ),
            max_attempts: 1,
            window: Duration::from_secs(60),
        };

        assert!(check(&limiter_a, "exhausted")?);
        assert!(
            !check_all(&limiter_b, ["fresh", "exhausted"])?,
            "composite admission must fail when any shared bucket is exhausted"
        );
        assert!(
            check(&limiter_a, "fresh")?,
            "failed composite admission must not consume fresh buckets"
        );
        assert!(!check(&limiter_b, "fresh")?);
        Ok(())
    }
}
