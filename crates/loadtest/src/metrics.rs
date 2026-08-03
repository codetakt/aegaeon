use anyhow::Result;
use prometheus::{register_counter_vec, register_histogram_vec, CounterVec, HistogramVec};
use std::sync::Arc;

/// Load test metrics
pub struct LoadTestMetrics {
    /// Request counter
    pub requests_total: CounterVec,

    /// Request latency histogram
    pub request_latency: HistogramVec,

    /// Error counter
    pub errors_total: CounterVec,
}

impl LoadTestMetrics {
    /// Construct the Prometheus metric set used by the loadtest runner.
    ///
    /// # Errors
    ///
    /// Returns an error when one of the metric registrations fails, typically because the metric
    /// name was already registered in the current process.
    pub fn new() -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            requests_total: register_counter_vec!(
                "loadtest_requests_total",
                "Total number of requests sent",
                &["scenario", "status"]
            )?,

            request_latency: register_histogram_vec!(
                "loadtest_request_latency_seconds",
                "Request latency in seconds",
                &["scenario"],
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
            )?,

            errors_total: register_counter_vec!(
                "loadtest_errors_total",
                "Total number of errors",
                &["scenario", "error_type"]
            )?,
        }))
    }

    pub fn record_request(&self, scenario: &str, success: bool, latency_seconds: f64) {
        let status = if success { "success" } else { "failure" };

        self.requests_total
            .with_label_values(&[scenario, status])
            .inc();

        self.request_latency
            .with_label_values(&[scenario])
            .observe(latency_seconds);
    }

    pub fn record_error(&self, scenario: &str, error_type: &str) {
        self.errors_total
            .with_label_values(&[scenario, error_type])
            .inc();
    }
}
