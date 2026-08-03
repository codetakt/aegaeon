#![forbid(unsafe_code)]
#![allow(clippy::multiple_crate_versions)]
// `prometheus` currently pulls `protobuf`/`thiserror` v1 while the
// OpenTelemetry stack uses `thiserror` v2. We allow this narrowly at the crate
// boundary until the upstream graph converges.
pub mod audit;
pub mod metrics;
pub mod tracing;

use std::sync::Arc;

/// Central observability configuration
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Enable audit logging
    pub audit_enabled: bool,

    /// Audit log retention days
    pub audit_retention_days: u32,

    /// Enable distributed tracing
    pub tracing_enabled: bool,

    /// OpenTelemetry collector endpoint
    pub otlp_endpoint: String,

    /// Service name for tracing
    pub service_name: String,

    /// Enable Prometheus metrics
    pub metrics_enabled: bool,

    /// Metrics endpoint port
    pub metrics_port: u16,

    /// Sampling rate for traces (0.0 to 1.0)
    pub trace_sampling_rate: f64,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            audit_enabled: true,
            audit_retention_days: 90,
            tracing_enabled: true,
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "aegaeon-oauth".to_string(),
            metrics_enabled: true,
            metrics_port: 9090,
            trace_sampling_rate: 0.1, // 10% sampling by default
        }
    }
}

/// Initialize all observability systems.
#[must_use]
pub fn init_observability(config: &ObservabilityConfig) -> ObservabilityHandle {
    let mut handle = ObservabilityHandle::default();

    if config.audit_enabled {
        handle.audit = Some(Arc::new(audit::AuditLogger::new(
            config.audit_retention_days,
        )));
    }

    if config.tracing_enabled {
        tracing::init_tracing(config);
    }

    if config.metrics_enabled {
        let registry = Arc::new(metrics::init_metrics());
        handle.metrics = Some(registry.clone());

        // Start metrics server
        tokio::spawn(metrics::serve_metrics(config.metrics_port, registry));
    }

    handle
}

/// Handle to observability systems
#[derive(Default, Clone)]
pub struct ObservabilityHandle {
    pub audit: Option<Arc<audit::AuditLogger>>,
    pub metrics: Option<Arc<prometheus::Registry>>,
}
