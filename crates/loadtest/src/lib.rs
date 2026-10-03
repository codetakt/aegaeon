#![forbid(unsafe_code)]
pub mod accounting;
pub mod generator;
pub mod metrics;
pub mod oidc;
pub mod profile;
pub mod scenarios;

use anyhow::{anyhow, Result};
use hdrhistogram::Histogram;
use num_traits::ToPrimitive;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Load test configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadTestConfig {
    /// Target server URL
    pub target_url: String,

    /// Number of concurrent workers
    pub workers: usize,

    /// Duration of the test
    pub duration: Duration,

    /// Requests per second target
    pub target_rps: f64,

    /// Warm-up duration
    pub warmup_duration: Duration,

    /// Test scenario
    pub scenario: TestScenario,

    /// Enable debug logging
    pub debug: bool,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            target_url: "http://localhost:8080".to_string(),
            workers: 10,
            duration: Duration::from_secs(60),
            target_rps: 100.0,
            warmup_duration: Duration::from_secs(10),
            scenario: TestScenario::Smoke,
            debug: false,
        }
    }
}

/// Test scenarios
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TestScenario {
    /// Smoke endpoints that should succeed on a bare server
    Smoke,

    /// Authorization code flow
    AuthorizationCode,

    /// Token introspection
    Introspection,

    /// Token revocation
    Revocation,

    /// DPoP-bound tokens
    DPoP,

    /// OIDC userinfo
    Userinfo,

    /// OAuth authorization server metadata
    Discovery,

    /// JWKS distribution
    Jwks,

    /// PAR flow
    PAR,

    /// Mixed scenario (all flows)
    Mixed,

    /// Mixed success-path and policy-rejection traffic
    PolicyMixed,

    /// Key rotation stress test
    KeyRotation,
}

impl TestScenario {
    pub fn requires_profile(&self) -> bool {
        !matches!(
            self,
            Self::Smoke | Self::Discovery | Self::Jwks | Self::KeyRotation
        )
    }
    pub fn requires_oidc(&self) -> bool {
        matches!(self, Self::Userinfo | Self::PolicyMixed)
    }
    pub fn requires_dpop(&self) -> bool {
        matches!(self, Self::DPoP | Self::Mixed)
    }
    /// Leg identity is chosen before execution, including failures before HTTP setup.
    pub fn leg(&self, iteration: u64) -> (String, bool) {
        let name = match self {
            Self::Smoke => {
                if iteration.is_multiple_of(2) {
                    "health"
                } else {
                    "system-version"
                }
            }
            Self::AuthorizationCode => "auth-code",
            Self::DPoP => "dpop",
            Self::PAR => "par",
            Self::Introspection => "introspection",
            Self::Revocation => "revocation",
            Self::Userinfo => "userinfo",
            Self::Discovery => "discovery",
            Self::Jwks => "jwks",
            Self::KeyRotation => "key-rotation",
            Self::Mixed => ["dpop", "introspection", "revocation", "par"][(iteration % 4) as usize],
            Self::PolicyMixed => [
                "introspection",
                "introspection-missing-client-auth",
                "revocation",
                "revocation-missing-client-auth",
                "userinfo",
                "userinfo-missing-authorization",
            ][(iteration % 6) as usize],
        };
        (
            name.into(),
            matches!(self, Self::PolicyMixed) && iteration % 6 % 2 == 1,
        )
    }
    pub fn required_legs(&self) -> Vec<String> {
        let count = match self {
            Self::Smoke => 2,
            Self::Mixed => 4,
            Self::PolicyMixed => 6,
            _ => 1,
        };
        (0..count).map(|i| self.leg(i).0).collect()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportIdentity {
    pub source_sha256: String,
    pub artifact_sha256: String,
    pub config_sha256: String,
    /// Exact UTF-8 serde JSON bytes hashed by config_sha256.
    pub config_json: String,
    pub report_id: String,
    pub report_path: String,
    pub profile_sha256: Option<String>,
    pub session_provenance_sha256: Option<String>,
}

/// Test results
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoadTestResults {
    pub schema_version: u32,
    pub request_unit: String,
    pub memory_subject: String,
    pub identity: Option<ReportIdentity>,
    pub selected_scenario: Option<TestScenario>,
    pub main_phase: accounting::PhaseAccounting,
    pub warmup_phase: accounting::PhaseAccounting,
    pub warmup_requested: bool,
    pub completion_errors: Vec<String>,
    pub jwks_sha256: Vec<String>,
    /// Total scenario invocations; this legacy field is not an HTTP counter.
    pub total_requests: u64,

    /// Successful requests
    pub successful_requests: u64,

    /// Failed requests
    pub failed_requests: u64,

    /// Latency histogram
    #[serde(skip, default = "LoadTestResults::default_histogram")]
    pub latency_histogram: Arc<RwLock<Histogram<u64>>>,

    /// Successful throughput (successful requests per second)
    pub throughput: f64,

    /// Attempted throughput (total requests per second)
    pub attempted_throughput: f64,

    /// p50 latency in milliseconds
    pub p50_latency_ms: f64,

    /// p99 latency in milliseconds
    pub p99_latency_ms: f64,

    /// p999 latency in milliseconds
    pub p999_latency_ms: f64,

    /// Maximum latency in milliseconds
    pub max_latency_ms: f64,

    /// Error rate (failed / total)
    pub error_rate: f64,

    /// Peak memory usage in MB
    pub peak_memory_mb: f64,

    /// Average memory usage in MB
    pub avg_memory_mb: f64,

    /// Test duration
    pub duration: Duration,

    /// Error categories
    pub error_categories: std::collections::HashMap<String, u64>,

    /// Memory samples over time
    pub memory_samples: Vec<f64>,
}

impl LoadTestResults {
    fn build_histogram() -> Result<Arc<RwLock<Histogram<u64>>>> {
        Histogram::<u64>::new_with_bounds(1, 60_000, 3)
            .map(|histogram| Arc::new(RwLock::new(histogram)))
            .map_err(|error| anyhow!("failed to create latency histogram: {error}"))
    }

    #[must_use]
    fn default_histogram() -> Arc<RwLock<Histogram<u64>>> {
        match Self::build_histogram() {
            Ok(histogram) => histogram,
            Err(_) => std::process::abort(),
        }
    }

    #[must_use]
    fn count_as_f64(value: u64) -> f64 {
        value.to_f64().unwrap_or(f64::from(u32::MAX))
    }

    #[must_use]
    fn len_as_f64(value: usize) -> f64 {
        value.to_f64().unwrap_or(f64::from(u32::MAX))
    }

    /// Construct a fresh result accumulator.
    ///
    /// # Errors
    ///
    /// Returns an error when the latency histogram cannot be initialized.
    pub fn try_new() -> Result<Self> {
        Ok(Self {
            schema_version: 2,
            request_unit: "scenario_invocations".into(),
            memory_subject: "load_generator_process".into(),
            identity: None,
            selected_scenario: None,
            main_phase: accounting::PhaseAccounting::default(),
            warmup_phase: accounting::PhaseAccounting::default(),
            warmup_requested: false,
            completion_errors: Vec::new(),
            jwks_sha256: Vec::new(),
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            latency_histogram: Self::build_histogram()?,
            throughput: 0.0,
            attempted_throughput: 0.0,
            p50_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            p999_latency_ms: 0.0,
            max_latency_ms: 0.0,
            error_rate: 0.0,
            peak_memory_mb: 0.0,
            avg_memory_mb: 0.0,
            duration: Duration::from_secs(0),
            error_categories: std::collections::HashMap::new(),
            memory_samples: Vec::new(),
        })
    }

    pub async fn record_request(&mut self, latency_ms: u64, success: bool, error: Option<String>) {
        self.total_requests += 1;

        if success {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
            if let Some(err) = error {
                *self.error_categories.entry(err).or_insert(0) += 1;
            }
        }

        let mut hist = self.latency_histogram.write().await;
        if hist.record(latency_ms).is_err() {
            self.completion_errors
                .push("scenario latency exceeds histogram bounds".into());
        }
    }

    pub fn record_memory_sample(&mut self, memory_mb: f64) {
        self.memory_samples.push(memory_mb);
        if memory_mb > self.peak_memory_mb {
            self.peak_memory_mb = memory_mb;
        }
    }

    pub async fn finalize(&mut self, duration: Duration) {
        self.duration = duration;
        let duration_secs = duration.as_secs_f64().max(f64::EPSILON);
        self.attempted_throughput = Self::count_as_f64(self.total_requests) / duration_secs;
        self.throughput = Self::count_as_f64(self.successful_requests) / duration_secs;
        self.error_rate = if self.total_requests == 0 {
            1.0
        } else {
            Self::count_as_f64(self.failed_requests) / Self::count_as_f64(self.total_requests)
        };

        let hist = self.latency_histogram.read().await;
        self.p50_latency_ms = Self::count_as_f64(hist.value_at_percentile(50.0));
        self.p99_latency_ms = Self::count_as_f64(hist.value_at_percentile(99.0));
        self.p999_latency_ms = Self::count_as_f64(hist.value_at_percentile(99.9));
        self.max_latency_ms = Self::count_as_f64(hist.max());

        // Calculate average memory usage
        if !self.memory_samples.is_empty() {
            self.avg_memory_mb = self.memory_samples.iter().sum::<f64>()
                / Self::len_as_f64(self.memory_samples.len());
        }
    }

    pub fn print_summary(&self, target_rps: f64) {
        let total_requests = self.total_requests.max(1);
        let success_percent = (Self::count_as_f64(self.successful_requests)
            / Self::count_as_f64(total_requests))
            * 100.0;
        let failed_percent =
            (Self::count_as_f64(self.failed_requests) / Self::count_as_f64(total_requests)) * 100.0;
        let min_successful_throughput = (target_rps * 0.9).max(1.0);
        let max_error_rate = 0.01;

        println!("\n========== Load Test Results ==========");
        println!("Duration: {:?}", self.duration);
        println!(
            "Scenario invocations (legacy total_requests): {}",
            self.total_requests
        );
        println!("HTTP attempts: {}", self.main_phase.http.attempts);
        println!(
            "Successful: {} ({:.2}%)",
            self.successful_requests, success_percent
        );
        println!("Failed: {} ({:.2}%)", self.failed_requests, failed_percent);
        println!(
            "Successful throughput: {:.2} invocations/s",
            self.throughput
        );
        println!(
            "Attempted throughput:  {:.2} req/s",
            self.attempted_throughput
        );
        println!("Error rate: {:.2}%", self.error_rate * 100.0);
        println!("\n---------- Latency (ms) ----------");
        println!("p50:  {:.2}", self.p50_latency_ms);
        println!("p99:  {:.2}", self.p99_latency_ms);
        println!("p999: {:.2}", self.p999_latency_ms);
        println!("max:  {:.2}", self.max_latency_ms);

        println!("\n---------- Load Generator Memory (MB) ----------");
        println!("Peak:    {:.2}", self.peak_memory_mb);
        println!("Average: {:.2}", self.avg_memory_mb);

        if !self.error_categories.is_empty() {
            println!("\n---------- Error Categories ----------");
            for (category, count) in &self.error_categories {
                println!("{category}: {count}");
            }
        }

        // Check SLOs
        println!("\n---------- SLO Validation ----------");
        let slo_p50_pass = self.p50_latency_ms <= 50.0;
        let slo_p99_pass = self.p99_latency_ms <= 200.0;
        let slo_throughput_pass = self.throughput >= min_successful_throughput;
        let slo_error_rate_pass = self.total_requests > 0 && self.error_rate <= max_error_rate;
        let slo_memory_pass = self.peak_memory_mb <= 500.0;

        println!(
            "p50 < 50ms: {} (actual: {:.2}ms)",
            if slo_p50_pass { "✓ PASS" } else { "✗ FAIL" },
            self.p50_latency_ms
        );
        println!(
            "p99 < 200ms: {} (actual: {:.2}ms)",
            if slo_p99_pass { "✓ PASS" } else { "✗ FAIL" },
            self.p99_latency_ms
        );
        println!(
            "Successful throughput >= {:.0} req/s: {} (actual: {:.2} req/s; target: {:.0} req/s)",
            min_successful_throughput,
            if slo_throughput_pass {
                "✓ PASS"
            } else {
                "✗ FAIL"
            },
            self.throughput,
            target_rps,
        );
        println!(
            "Error rate <= {:.2}%: {} (actual: {:.2}%)",
            max_error_rate * 100.0,
            if slo_error_rate_pass {
                "✓ PASS"
            } else {
                "✗ FAIL"
            },
            self.error_rate * 100.0,
        );
        println!(
            "Memory < 500MB: {} (peak: {:.2}MB)",
            if slo_memory_pass {
                "✓ PASS"
            } else {
                "✗ FAIL"
            },
            self.peak_memory_mb
        );

        let all_slos_pass = self.validate_complete().is_ok()
            && slo_p50_pass
            && slo_p99_pass
            && slo_throughput_pass
            && slo_error_rate_pass
            && slo_memory_pass;
        println!(
            "\nOverall SLO Status: {}",
            if all_slos_pass {
                "✓ ALL PASS"
            } else {
                "✗ SOME FAILED"
            }
        );
        println!("======================================\n");
    }

    #[must_use]
    pub fn meets_slos(&self, target_rps: f64) -> bool {
        let min_throughput = (target_rps * 0.9).max(1.0);
        let max_error_rate = 0.01;
        target_rps.is_finite()
            && target_rps > 0.0
            && self.validate_complete().is_ok()
            && self.p50_latency_ms <= 50.0
            && self.p99_latency_ms <= 200.0
            && self.throughput >= min_throughput
            && self.total_requests > 0
            && self.error_rate <= max_error_rate
            && self.peak_memory_mb <= 500.0
    }

    pub fn validate_complete(&self) -> Result<()> {
        use anyhow::ensure;
        ensure!(
            self.schema_version == 2
                && self.request_unit == "scenario_invocations"
                && self.memory_subject == "load_generator_process",
            "report unit/schema mismatch"
        );
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow!("missing report identity"))?;
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
        };
        ensure!(
            digest(&identity.source_sha256)
                && digest(&identity.artifact_sha256)
                && digest(&identity.config_sha256)
                && !identity.report_id.is_empty()
                && !identity.report_path.is_empty(),
            "missing or invalid source/artifact/config/report identity"
        );
        let scenario = self
            .selected_scenario
            .as_ref()
            .ok_or_else(|| anyhow!("missing selected scenario"))?;
        ensure!(
            profile::sha256(identity.config_json.as_bytes()) == identity.config_sha256,
            "configuration witness digest mismatch"
        );
        let config: LoadTestConfig = serde_json::from_str(&identity.config_json)?;
        ensure!(
            config.workers > 0
                && config.target_rps.is_finite()
                && config.target_rps > 0.0
                && !config.duration.is_zero()
                && serde_json::to_value(&config.scenario)? == serde_json::to_value(scenario)?
                && self.warmup_requested != config.warmup_duration.is_zero(),
            "configuration witness differs from selected execution"
        );
        if scenario.requires_profile() {
            ensure!(
                identity.profile_sha256.as_deref().is_some_and(digest)
                    && identity
                        .session_provenance_sha256
                        .as_deref()
                        .is_some_and(digest),
                "missing profile/session supplier identity"
            );
        }
        ensure!(
            self.completion_errors.is_empty(),
            "load test has setup/join/accounting failures"
        );
        self.main_phase.validate(&scenario.required_legs())?;
        if self.warmup_requested {
            self.warmup_phase.validate(&scenario.required_legs())?;
        }
        let total = self
            .main_phase
            .legs
            .values()
            .try_fold(0u64, |a, v| a.checked_add(v.invocations))
            .ok_or_else(|| anyhow!("scenario counter overflow"))?;
        ensure!(
            self.successful_requests.checked_add(self.failed_requests) == Some(self.total_requests)
                && self.total_requests == total
                && self.failed_requests == 0,
            "failed or inconsistent scenario accounting"
        );
        ensure!(
            [
                self.throughput,
                self.attempted_throughput,
                self.p50_latency_ms,
                self.p99_latency_ms,
                self.p999_latency_ms,
                self.max_latency_ms,
                self.error_rate,
                self.peak_memory_mb,
                self.avg_memory_mb
            ]
            .into_iter()
            .all(|v| v.is_finite() && v >= 0.0)
                && !self.duration.is_zero()
                && !self.memory_samples.is_empty()
                && self
                    .memory_samples
                    .iter()
                    .all(|v| v.is_finite() && *v >= 0.0),
            "missing or nonfinite measurement"
        );
        Ok(())
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;
    #[tokio::test]
    async fn report_rejects_missing_identity_counts_nonfinite_and_selected_legs() {
        let mut report = LoadTestResults::try_new().unwrap();
        report.selected_scenario = Some(TestScenario::PolicyMixed);
        assert!(report.validate_complete().is_err());
        let config_json = serde_json::to_string(&LoadTestConfig {
            scenario: TestScenario::PolicyMixed,
            warmup_duration: Duration::ZERO,
            ..LoadTestConfig::default()
        })
        .unwrap();
        report.identity = Some(ReportIdentity {
            source_sha256: "a".repeat(64),
            artifact_sha256: "b".repeat(64),
            config_sha256: profile::sha256(config_json.as_bytes()),
            config_json,
            report_id: "report".into(),
            report_path: "report.json".into(),
            profile_sha256: Some("d".repeat(64)),
            session_provenance_sha256: Some("e".repeat(64)),
        });
        for i in 0..6 {
            let (leg, rejection) = TestScenario::PolicyMixed.leg(i);
            report
                .main_phase
                .legs
                .entry(leg)
                .or_default()
                .record(true, rejection);
            report.record_request(10, true, None).await;
        }
        report.main_phase.http.attempts = 6;
        report.main_phase.http.responses = 6;
        report
            .main_phase
            .http
            .methods_endpoints
            .insert("GET /test".into(), 6);
        report
            .main_phase
            .http
            .statuses
            .insert("GET /test 200".into(), 6);
        report.record_memory_sample(10.0);
        report.finalize(Duration::from_secs(1)).await;
        assert!(report.validate_complete().is_ok());
        let saved = report.identity.as_ref().unwrap().clone();
        report.identity.as_mut().unwrap().config_json.push(' ');
        assert!(report.validate_complete().is_err());
        report.identity = Some(saved.clone());
        for raw in [
            saved.config_json.replace("PolicyMixed", "Smoke"),
            saved.config_json.replace("\"secs\":0", "\"secs\":1"),
            saved.config_json.replacen("{", "{\"unexpected\":true,", 1),
            saved.config_json.replacen("{", "{\"workers\":3,", 1),
            "{}".into(),
        ] {
            report.identity.as_mut().unwrap().config_sha256 = profile::sha256(raw.as_bytes());
            report.identity.as_mut().unwrap().config_json = raw;
            assert!(report.validate_complete().is_err());
        }
        report.identity = Some(saved);
        assert!(report.meets_slos(6.0));
        report.throughput = f64::NAN;
        assert!(!report.meets_slos(6.0));
        report.throughput = 6.0;
        report
            .main_phase
            .legs
            .remove("userinfo-missing-authorization");
        assert!(report.validate_complete().is_err());
        report
            .main_phase
            .legs
            .entry("userinfo-missing-authorization".into())
            .or_default()
            .record(true, true);
        report.total_requests = 7;
        assert!(report.validate_complete().is_err());
    }
}
