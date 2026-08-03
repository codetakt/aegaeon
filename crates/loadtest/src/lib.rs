#![forbid(unsafe_code)]
pub mod generator;
pub mod metrics;
pub mod scenarios;

use anyhow::{anyhow, Result};
use hdrhistogram::Histogram;
use num_traits::ToPrimitive;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Load test configuration
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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

/// Test results
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoadTestResults {
    /// Total requests sent
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
        let _ = hist.record(latency_ms);
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
        println!("Total Requests: {}", self.total_requests);
        println!(
            "Successful: {} ({:.2}%)",
            self.successful_requests, success_percent
        );
        println!("Failed: {} ({:.2}%)", self.failed_requests, failed_percent);
        println!("Successful throughput: {:.2} req/s", self.throughput);
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

        println!("\n---------- Memory Usage (MB) ----------");
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

        let all_slos_pass = slo_p50_pass
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
        self.p50_latency_ms <= 50.0
            && self.p99_latency_ms <= 200.0
            && self.throughput >= min_throughput
            && self.total_requests > 0
            && self.error_rate <= max_error_rate
            && self.peak_memory_mb <= 500.0
    }
}
