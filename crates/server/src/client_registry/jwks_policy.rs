use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::{
    test_runtime_helpers_allowed_by_build, try_env_flag, try_env_optional_string, ConfigError,
};

mod managed;

use self::managed::JwksManagedRuntimePolicy;

pub(super) const MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS: u64 = 86_400;
pub(super) const MAX_JWKS_CACHE_TTL_SECS: u64 = MAX_JWKS_CACHE_CONTROL_MAX_AGE_SECS;
pub(super) const MAX_JWKS_CACHE_GC_INTERVAL_SECS: u64 = 86_400;
pub(super) const MAX_JWKS_HTTP_TIMEOUT_SECS: u64 = 60;
pub(super) const MAX_JWKS_HTTP_RETRIES: u32 = 10;
pub(super) const MAX_JWKS_CIRCUIT_OPEN_FAILS: u32 = 1_000;
pub(super) const MAX_JWKS_CIRCUIT_RESET_SECS: u64 = 3_600;
pub(super) const MAX_JWKS_REFRESH_SKEW_SECS: u64 = 3_600;
pub(super) const MAX_JWKS_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const DEFAULT_JWKS_LOCAL_CACHE_MAX_ENTRIES: usize = 4096;
pub(super) const MAX_JWKS_LOCAL_CACHE_MAX_ENTRIES: u32 = 1_000_000;
pub(super) const DEFAULT_JWKS_HTTP_LATENCY_BUCKETS: &[f64] =
    &[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];
const JWKS_HISTOGRAM_BUCKETS_ENV: &str = "AEGAEON_JWKS_HISTOGRAM_BUCKETS";
const JWKS_LOG_SAMPLE_PERCENT_ENV: &str = "AEGAEON_JWKS_LOG_SAMPLE_PERCENT";
const JWKS_CA_BUNDLE_ENV: &str = "AEGAEON_JWKS_CA_BUNDLE";
const JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV: &str = "AEGAEON_JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS";
const JWKS_INSECURE_SKIP_VERIFY_ENV: &str = "AEGAEON_JWKS_INSECURE_SKIP_VERIFY";
const JWKS_OUTCOME_LOG_SAMPLE_ENV_KEYS: &[(&str, &str)] = &[
    ("200", "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_200"),
    ("304", "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_304"),
    ("FAILURE", "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_FAILURE"),
    ("ERROR", "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_ERROR"),
];
#[cfg(test)]
const JWKS_HOST_LOCAL_BOOTSTRAP_ENV_KEYS: &[&str] = &[
    JWKS_HISTOGRAM_BUCKETS_ENV,
    JWKS_LOG_SAMPLE_PERCENT_ENV,
    "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_200",
    "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_304",
    "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_FAILURE",
    "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_ERROR",
    JWKS_CA_BUNDLE_ENV,
    JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV,
    JWKS_INSECURE_SKIP_VERIFY_ENV,
];

pub(super) const fn valid_jwks_cache_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_JWKS_CACHE_TTL_SECS
}

pub(super) const fn valid_jwks_cache_gc_interval_secs(value: u64) -> bool {
    value > 0 && value <= MAX_JWKS_CACHE_GC_INTERVAL_SECS
}

pub(super) const fn valid_jwks_http_timeout_secs(value: u64) -> bool {
    value > 0 && value <= MAX_JWKS_HTTP_TIMEOUT_SECS
}

pub(super) const fn valid_jwks_http_retries(value: u32) -> bool {
    value <= MAX_JWKS_HTTP_RETRIES
}

pub(super) const fn valid_jwks_circuit_open_fails(value: u32) -> bool {
    value > 0 && value <= MAX_JWKS_CIRCUIT_OPEN_FAILS
}

pub(super) const fn valid_jwks_circuit_reset_secs(value: u64) -> bool {
    value > 0 && value <= MAX_JWKS_CIRCUIT_RESET_SECS
}

pub(super) const fn valid_jwks_refresh_skew_secs(value: u64) -> bool {
    value <= MAX_JWKS_REFRESH_SKEW_SECS
}

pub(super) const fn valid_jwks_max_body_bytes(value: usize) -> bool {
    value > 0 && value <= MAX_JWKS_MAX_BODY_BYTES
}

pub(super) const fn valid_jwks_local_cache_max_entries(value: u32) -> bool {
    value > 0 && value <= MAX_JWKS_LOCAL_CACHE_MAX_ENTRIES
}

fn try_env_optional_num_with<T>(
    key: &str,
    is_valid: impl FnOnce(T) -> bool,
    expectation: &str,
) -> Result<Option<T>, ConfigError>
where
    T: Copy + std::fmt::Display + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = match std::env::var(key) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ConfigError::NonUnicode {
                key: key.to_string(),
            });
        }
    };
    let parsed = value
        .trim()
        .parse::<T>()
        .map_err(|err| ConfigError::InvalidNumber {
            key: key.to_string(),
            value: value.clone(),
            reason: err.to_string(),
        })?;
    if !is_valid(parsed) {
        return Err(ConfigError::InvalidNumberRange {
            key: key.to_string(),
            value: parsed.to_string(),
            expectation: expectation.to_string(),
        });
    }
    Ok(Some(parsed))
}

fn parse_histogram_buckets(raw: &str) -> Result<Vec<f64>, ConfigError> {
    let buckets = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.parse::<f64>()
                .map_err(|err| ConfigError::InvalidNumber {
                    key: JWKS_HISTOGRAM_BUCKETS_ENV.to_string(),
                    value: item.to_string(),
                    reason: err.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if buckets.is_empty()
        || buckets
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err(ConfigError::InvalidValue {
            key: JWKS_HISTOGRAM_BUCKETS_ENV.to_string(),
            value: raw.to_string(),
            reason: "must contain positive finite numeric buckets".to_string(),
        });
    }
    Ok(buckets)
}

fn try_test_only_env_flag(key: &'static str) -> Result<bool, ConfigError> {
    let enabled = try_env_flag(key, false)?;
    if enabled && !test_runtime_helpers_allowed_by_build() {
        return Err(ConfigError::InvalidValue {
            key: key.to_string(),
            value: "true".to_string(),
            reason: "this JWKS test-only transport override is unavailable in release builds"
                .to_string(),
        });
    }
    Ok(enabled)
}

fn default_jwks_http_latency_buckets() -> Vec<f64> {
    DEFAULT_JWKS_HTTP_LATENCY_BUCKETS.to_vec()
}

fn try_jwks_histogram_buckets_from_env() -> Result<Vec<f64>, ConfigError> {
    let raw = match std::env::var(JWKS_HISTOGRAM_BUCKETS_ENV) {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(default_jwks_http_latency_buckets()),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(ConfigError::NonUnicode {
                key: JWKS_HISTOGRAM_BUCKETS_ENV.to_string(),
            });
        }
    };
    parse_histogram_buckets(&raw)
}

fn try_jwks_log_sample_percent_from_env(key: &str) -> Result<Option<u8>, ConfigError> {
    try_env_optional_num_with(key, |value: u8| value <= 100, "a percentage in 0..=100")
}

fn try_jwks_outcome_log_sample_percent_from_env() -> Result<HashMap<String, u8>, ConfigError> {
    JWKS_OUTCOME_LOG_SAMPLE_ENV_KEYS.iter().try_fold(
        HashMap::new(),
        |mut sampling, (outcome, key)| {
            if let Some(percent) = try_jwks_log_sample_percent_from_env(key)? {
                sampling.insert((*outcome).to_string(), percent);
            }
            Ok(sampling)
        },
    )
}

fn normalized_optional_path_from_env(key: &str) -> Result<Option<PathBuf>, ConfigError> {
    Ok(try_env_optional_string(key)?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from))
}

#[derive(Clone, Debug)]
pub struct JwksRuntimePolicy {
    pub(super) allow_http_loopback_for_tests: bool,
    pub(super) insecure_skip_verify: bool,
    pub(super) allow_kid_reuse: bool,
    pub(super) circuit_open_fails: u32,
    pub(super) circuit_reset_secs: u64,
    pub(super) cache_ttl_secs: u64,
    pub(super) cache_gc_interval_secs: u64,
    pub(super) http_timeout_secs: u64,
    pub(super) refresh_skew_secs: u64,
    pub(super) shared_state_max_age_secs: u64,
    pub(super) local_cache_max_entries: usize,
    pub(super) max_body_bytes: usize,
    pub(super) http_retries: u32,
    pub(super) log_sample_percent: u8,
    pub(super) outcome_log_sample_percent: HashMap<String, u8>,
    pub(super) histogram_buckets: Vec<f64>,
    pub(super) ca_bundle: Option<PathBuf>,
}

impl Default for JwksRuntimePolicy {
    fn default() -> Self {
        Self {
            allow_http_loopback_for_tests: false,
            insecure_skip_verify: false,
            allow_kid_reuse: false,
            circuit_open_fails: 3,
            circuit_reset_secs: 30,
            cache_ttl_secs: 300,
            cache_gc_interval_secs: 600,
            http_timeout_secs: 5,
            refresh_skew_secs: 10,
            shared_state_max_age_secs: MAX_JWKS_CACHE_TTL_SECS,
            local_cache_max_entries: DEFAULT_JWKS_LOCAL_CACHE_MAX_ENTRIES,
            max_body_bytes: 64 * 1024,
            http_retries: 2,
            log_sample_percent: 5,
            outcome_log_sample_percent: HashMap::new(),
            histogram_buckets: default_jwks_http_latency_buckets(),
            ca_bundle: None,
        }
    }
}

impl JwksRuntimePolicy {
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_for_tests_allowing_loopback() -> Self {
        Self {
            allow_http_loopback_for_tests: true,
            ..Self::default()
        }
    }

    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_for_tests_with_loopback_circuit(
        circuit_open_fails: u32,
        circuit_reset_secs: u64,
        refresh_skew_secs: u64,
    ) -> Self {
        Self {
            allow_http_loopback_for_tests: true,
            circuit_open_fails,
            circuit_reset_secs,
            refresh_skew_secs,
            ..Self::default()
        }
    }

    fn with_managed_runtime_policy(mut self, managed: JwksManagedRuntimePolicy) -> Self {
        self.allow_kid_reuse = managed.allow_kid_reuse;
        self.circuit_open_fails = managed.circuit_open_fails;
        self.circuit_reset_secs = managed.circuit_reset_secs;
        self.cache_ttl_secs = managed.cache_ttl_secs;
        self.cache_gc_interval_secs = managed.cache_gc_interval_secs;
        self.http_timeout_secs = managed.http_timeout_secs;
        self.refresh_skew_secs = managed.refresh_skew_secs;
        self.shared_state_max_age_secs = managed.shared_state_max_age_secs;
        self.local_cache_max_entries = managed.local_cache_max_entries as usize;
        self.max_body_bytes = managed.max_body_bytes;
        self.http_retries = managed.http_retries;
        self
    }

    fn try_bootstrap_from_env() -> Result<Self, ConfigError> {
        let histogram_buckets = try_jwks_histogram_buckets_from_env()?;
        Ok(Self {
            allow_http_loopback_for_tests: try_test_only_env_flag(
                JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV,
            )?,
            insecure_skip_verify: try_test_only_env_flag(JWKS_INSECURE_SKIP_VERIFY_ENV)?,
            log_sample_percent: try_jwks_log_sample_percent_from_env(JWKS_LOG_SAMPLE_PERCENT_ENV)?
                .unwrap_or(5),
            outcome_log_sample_percent: try_jwks_outcome_log_sample_percent_from_env()?,
            histogram_buckets,
            ca_bundle: normalized_optional_path_from_env(JWKS_CA_BUNDLE_ENV)?,
            ..Self::default()
        })
    }

    /// Build JWKS runtime policy from the management database policy snapshot plus host-local
    /// bootstrap settings such as CA bundles and observability sampling.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when either the policy snapshot or bootstrap-only environment is
    /// outside supported bounds.
    pub fn try_from_management_policy(
        policy: &crate::management::types::PolicyDocument,
    ) -> Result<Self, ConfigError> {
        let bootstrap = Self::try_bootstrap_from_env()?;
        JwksManagedRuntimePolicy::try_from_management_policy(policy)
            .map(|managed| bootstrap.with_managed_runtime_policy(managed))
    }

    /// Validate only the database-managed JWKS policy fields.
    ///
    /// This deliberately avoids host-local bootstrap environment so management API validation does
    /// not depend on process-local CA bundle, path, or observability settings.
    pub fn validate_management_policy(
        policy: &crate::management::types::PolicyDocument,
    ) -> Result<(), ConfigError> {
        JwksManagedRuntimePolicy::try_from_management_policy(policy).map(|_| ())
    }

    pub(super) fn log_sample_percent_for(&self, outcome: &str) -> u8 {
        self.outcome_log_sample_percent
            .get(&outcome.to_ascii_uppercase())
            .copied()
            .unwrap_or(self.log_sample_percent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn host_local_bootstrap_env_inventory_is_complete() {
        let inventory = JWKS_HOST_LOCAL_BOOTSTRAP_ENV_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let outcome_keys = JWKS_OUTCOME_LOG_SAMPLE_ENV_KEYS
            .iter()
            .map(|(_, key)| *key)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            inventory,
            BTreeSet::from([
                JWKS_HISTOGRAM_BUCKETS_ENV,
                JWKS_LOG_SAMPLE_PERCENT_ENV,
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_200",
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_304",
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_FAILURE",
                "AEGAEON_JWKS_LOG_SAMPLE_PERCENT_ERROR",
                JWKS_CA_BUNDLE_ENV,
                JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS_ENV,
                JWKS_INSECURE_SKIP_VERIFY_ENV,
            ])
        );
        assert!(outcome_keys.is_subset(&inventory));
    }
}
