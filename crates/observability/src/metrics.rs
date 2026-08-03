use anyhow::Result;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use prometheus::{
    register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_gauge_with_registry, register_histogram_vec_with_registry, CounterVec, Encoder, Gauge,
    GaugeVec, HistogramVec, Registry, TextEncoder,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

struct ProfileCounters {
    operations: CounterVec,
    usage: CounterVec,
    rejections: CounterVec,
}

struct RateGauges {
    dpop_failure: Gauge,
    pkce_mismatch: Gauge,
    par_usage: Gauge,
}

fn register_profile_counters(registry: &Registry) -> Result<ProfileCounters> {
    Ok(ProfileCounters {
        operations: register_counter_vec_with_registry!(
            "oauth_profile_operations_total",
            "OAuth profile lifecycle operations",
            &["operation", "status"],
            registry
        )?,
        usage: register_counter_vec_with_registry!(
            "oauth_profile_usage_total",
            "OAuth profile usage by endpoint",
            &["profile_type", "endpoint"],
            registry
        )?,
        rejections: register_counter_vec_with_registry!(
            "oauth_profile_rejections_total",
            "OAuth profile rejections by reason",
            &["profile_type", "reason", "endpoint"],
            registry
        )?,
    })
}

fn register_histograms(registry: &Registry) -> Result<(HistogramVec, HistogramVec)> {
    Ok((
        register_histogram_vec_with_registry!(
            "oauth_request_latency_seconds",
            "Request latency in seconds",
            &["endpoint", "method"],
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
            registry
        )?,
        register_histogram_vec_with_registry!(
            "oauth_key_rotation_seconds",
            "Time taken for key rotation in seconds",
            &["key_type"],
            vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
            registry
        )?,
    ))
}

fn register_rate_gauges(registry: &Registry) -> Result<RateGauges> {
    Ok(RateGauges {
        dpop_failure: register_gauge_with_registry!(
            "oauth_dpop_failure_rate",
            "Current DPoP failure rate",
            registry
        )?,
        pkce_mismatch: register_gauge_with_registry!(
            "oauth_pkce_mismatch_rate",
            "Current PKCE mismatch rate",
            registry
        )?,
        par_usage: register_gauge_with_registry!(
            "oauth_par_usage_rate",
            "Current PAR usage rate",
            registry
        )?,
    })
}

fn plain_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
}

fn metrics_response(content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    use http::{header::CONTENT_TYPE, HeaderValue};

    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = StatusCode::OK;
    if let Ok(header_value) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(CONTENT_TYPE, header_value);
    }
    response
}

/// OAuth-specific metrics
pub struct OAuthMetrics {
    /// Registry reference for gathering metrics
    registry: Arc<Registry>,

    /// Authentication attempts counter
    pub auth_attempts: CounterVec,

    /// Authentication success counter
    pub auth_success: CounterVec,

    /// Token operations counter
    pub token_operations: CounterVec,

    /// `DPoP` validation failures
    pub dpop_failures: CounterVec,

    /// PKCE mismatch counter
    pub pkce_mismatches: CounterVec,

    /// PAR usage counter
    pub par_requests: CounterVec,

    /// Token introspection requests
    pub introspection_requests: CounterVec,

    /// Token revocation requests
    pub revocation_requests: CounterVec,

    /// Resource endpoint access outcomes
    pub resource_requests: CounterVec,

    /// Sender binding enforcement failures
    pub sender_binding_failures: CounterVec,

    /// Refresh policy violations
    pub refresh_policy_violations: CounterVec,

    /// Step-up authentication events
    pub stepup_events: CounterVec,

    /// OAuth profile operations
    pub oauth_profile_operations: CounterVec,

    /// OAuth profile usage (by profile type/version/endpoint)
    pub oauth_profile_usage: CounterVec,

    /// OAuth profile rejections (by reason)
    pub oauth_profile_rejections: CounterVec,

    /// Request latency histogram
    pub request_latency: HistogramVec,

    /// Active sessions gauge
    pub active_sessions: GaugeVec,

    /// Token cache size
    pub token_cache_size: GaugeVec,

    /// Key rotation time histogram
    pub key_rotation_time: HistogramVec,

    /// Calculated rate metrics
    pub dpop_failure_rate_gauge: Gauge,
    pub pkce_mismatch_rate_gauge: Gauge,
    pub par_usage_rate_gauge: Gauge,
}

impl OAuthMetrics {
    /// # Errors
    ///
    /// Returns an error when Prometheus metric registration fails, such as when
    /// a metric name is registered more than once in the same registry.
    pub fn new(registry: &Registry) -> Result<Self> {
        let profile_counters = register_profile_counters(registry)?;
        let (request_latency, key_rotation_time) = register_histograms(registry)?;
        let rate_gauges = register_rate_gauges(registry)?;

        Ok(Self {
            registry: Arc::new(registry.clone()),
            auth_attempts: register_counter_vec_with_registry!(
                "oauth_auth_attempts_total",
                "Total authentication attempts",
                &["grant_type", "client_id"],
                registry
            )?,

            auth_success: register_counter_vec_with_registry!(
                "oauth_auth_success_total",
                "Successful authentications",
                &["grant_type", "client_id"],
                registry
            )?,

            token_operations: register_counter_vec_with_registry!(
                "oauth_token_operations_total",
                "Token operations",
                &["operation", "token_type"],
                registry
            )?,

            dpop_failures: register_counter_vec_with_registry!(
                "oauth_dpop_failures_total",
                "DPoP validation failures",
                &["reason"],
                registry
            )?,

            pkce_mismatches: register_counter_vec_with_registry!(
                "oauth_pkce_mismatches_total",
                "PKCE verification mismatches",
                &["client_id"],
                registry
            )?,

            par_requests: register_counter_vec_with_registry!(
                "oauth_par_requests_total",
                "Pushed Authorization Requests",
                &["client_id", "status"],
                registry
            )?,

            introspection_requests: register_counter_vec_with_registry!(
                "oauth_introspection_requests_total",
                "Token introspection requests",
                &["token_type", "active"],
                registry
            )?,

            revocation_requests: register_counter_vec_with_registry!(
                "oauth_revocation_requests_total",
                "Token revocation requests",
                &["token_type", "status"],
                registry
            )?,

            resource_requests: register_counter_vec_with_registry!(
                "oauth_resource_requests_total",
                "Resource endpoint access outcomes",
                &["mode", "status"],
                registry
            )?,

            sender_binding_failures: register_counter_vec_with_registry!(
                "oauth_sender_binding_failures_total",
                "Sender binding enforcement failures",
                &["reason"],
                registry
            )?,

            refresh_policy_violations: register_counter_vec_with_registry!(
                "oauth_refresh_policy_violations_total",
                "Refresh policy violations (rotation/parent checks)",
                &["reason"],
                registry
            )?,

            stepup_events: register_counter_vec_with_registry!(
                "oauth_stepup_events_total",
                "Step-up authentication events",
                &["event"],
                registry
            )?,
            oauth_profile_operations: profile_counters.operations,
            oauth_profile_usage: profile_counters.usage,
            oauth_profile_rejections: profile_counters.rejections,
            request_latency,

            active_sessions: register_gauge_vec_with_registry!(
                "oauth_active_sessions",
                "Number of active sessions",
                &["session_type"],
                registry
            )?,

            token_cache_size: register_gauge_vec_with_registry!(
                "oauth_token_cache_size",
                "Size of token cache",
                &["cache_type"],
                registry
            )?,
            key_rotation_time,
            dpop_failure_rate_gauge: rate_gauges.dpop_failure,
            pkce_mismatch_rate_gauge: rate_gauges.pkce_mismatch,
            par_usage_rate_gauge: rate_gauges.par_usage,
        })
    }

    pub fn record_oauth_profile_operation(&self, operation: &str, status: &str) {
        self.oauth_profile_operations
            .with_label_values(&[operation, status])
            .inc();
    }

    pub fn record_oauth_profile_usage(&self, profile_type: &str, endpoint: &str) {
        self.oauth_profile_usage
            .with_label_values(&[profile_type, endpoint])
            .inc();
    }

    pub fn record_oauth_profile_rejection(&self, profile_type: &str, reason: &str, endpoint: &str) {
        self.oauth_profile_rejections
            .with_label_values(&[profile_type, reason, endpoint])
            .inc();
    }

    /// Record authentication attempt
    pub fn record_auth_attempt(&self, grant_type: &str, client_id: &str, success: bool) {
        self.auth_attempts
            .with_label_values(&[grant_type, client_id])
            .inc();

        if success {
            self.auth_success
                .with_label_values(&[grant_type, client_id])
                .inc();
        }
    }

    /// Record `DPoP` failure.
    pub fn record_dpop_failure(&self, reason: &str) {
        self.dpop_failures.with_label_values(&[reason]).inc();
    }

    /// Record sender binding failure reason
    pub fn record_sender_binding_failure(&self, reason: &str) {
        self.sender_binding_failures
            .with_label_values(&[reason])
            .inc();
    }

    /// Record refresh policy violation reason
    pub fn record_refresh_policy_violation(&self, reason: &str) {
        self.refresh_policy_violations
            .with_label_values(&[reason])
            .inc();
    }

    /// Record step-up events
    pub fn record_stepup_event(&self, event: &str) {
        self.stepup_events.with_label_values(&[event]).inc();
    }

    /// Record PKCE mismatch
    pub fn record_pkce_mismatch(&self, client_id: &str) {
        self.pkce_mismatches.with_label_values(&[client_id]).inc();
    }

    /// Record PAR request
    pub fn record_par_request(&self, client_id: &str, success: bool) {
        let status = if success { "success" } else { "failure" };
        self.par_requests
            .with_label_values(&[client_id, status])
            .inc();
    }

    /// Record introspection request
    pub fn record_introspection(&self, token_type: &str, active: bool) {
        let active_str = if active { "true" } else { "false" };
        self.introspection_requests
            .with_label_values(&[token_type, active_str])
            .inc();
    }

    /// Record revocation request
    pub fn record_revocation(&self, token_type: &str, success: bool) {
        let status = if success { "success" } else { "failure" };
        self.revocation_requests
            .with_label_values(&[token_type, status])
            .inc();
    }

    /// Record request latency
    pub fn record_latency(&self, endpoint: &str, method: &str, latency_seconds: f64) {
        self.request_latency
            .with_label_values(&[endpoint, method])
            .observe(latency_seconds);
    }

    /// Update active sessions
    pub fn set_active_sessions(&self, session_type: &str, count: f64) {
        self.active_sessions
            .with_label_values(&[session_type])
            .set(count);
    }

    /// Update token cache size
    pub fn set_token_cache_size(&self, cache_type: &str, size: f64) {
        self.token_cache_size
            .with_label_values(&[cache_type])
            .set(size);
    }

    /// Record key rotation time
    pub fn record_key_rotation(&self, key_type: &str, duration_seconds: f64) {
        self.key_rotation_time
            .with_label_values(&[key_type])
            .observe(duration_seconds);
    }

    /// Calculate `DPoP` failure rate.
    #[must_use]
    pub fn dpop_failure_rate(&self) -> f64 {
        // Get total DPoP attempts (all token operations with DPoP)
        let dpop_attempts = self
            .token_operations
            .with_label_values(&["dpop_bound", "access_token"])
            .get()
            + self
                .token_operations
                .with_label_values(&["dpop_bound", "refresh_token"])
                .get();

        // Get total DPoP failures
        let mut dpop_failures = 0.0;
        let failure_reasons = vec![
            "invalid_proof",
            "expired",
            "wrong_htm",
            "wrong_htu",
            "replay",
        ];
        for reason in failure_reasons {
            dpop_failures += self.dpop_failures.with_label_values(&[reason]).get();
        }

        if dpop_attempts > 0.0 {
            dpop_failures / dpop_attempts
        } else {
            0.0
        }
    }

    /// Calculate PKCE mismatch rate.
    #[must_use]
    pub fn pkce_mismatch_rate(&self) -> f64 {
        // Get total PKCE verification attempts (auth code exchanges)
        let pkce_attempts = self
            .auth_attempts
            .with_label_values(&["authorization_code", "all"])
            .get();

        // Get total PKCE mismatches
        let mut pkce_mismatches_total = 0.0;
        // Sum up mismatches across all client IDs
        let metric_families = self.registry.gather();
        for family in &metric_families {
            if family.name() == "oauth_pkce_mismatches_total" {
                for metric in &family.metric {
                    if let Some(counter) = metric.counter.as_ref() {
                        pkce_mismatches_total += counter.value.unwrap_or(0.0);
                    }
                }
            }
        }

        if pkce_attempts > 0.0 {
            pkce_mismatches_total / pkce_attempts
        } else {
            0.0
        }
    }

    /// Update all rate gauge metrics.
    pub fn update_rate_metrics(&self) {
        self.dpop_failure_rate_gauge.set(self.dpop_failure_rate());
        self.pkce_mismatch_rate_gauge.set(self.pkce_mismatch_rate());
        self.par_usage_rate_gauge.set(self.par_usage_rate());
    }

    /// Calculate `PAR` usage rate.
    #[must_use]
    pub fn par_usage_rate(&self) -> f64 {
        // Get total authorization requests
        let total_auth_requests = self
            .auth_attempts
            .with_label_values(&["authorization_code", "all"])
            .get()
            + self
                .auth_attempts
                .with_label_values(&["implicit", "all"])
                .get();

        // Get PAR requests (successful + failed)
        let mut par_requests_total = 0.0;
        let metric_families = self.registry.gather();
        for family in &metric_families {
            if family.name() == "oauth_par_requests_total" {
                for metric in &family.metric {
                    if let Some(counter) = metric.counter.as_ref() {
                        par_requests_total += counter.value.unwrap_or(0.0);
                    }
                }
            }
        }

        if total_auth_requests > 0.0 {
            par_requests_total / total_auth_requests
        } else {
            0.0
        }
    }
}

/// Initialize metrics registry with OAuth metrics.
#[must_use]
pub fn init_metrics() -> Registry {
    Registry::new()
}

/// Serve metrics on the HTTP endpoint.
///
/// # Errors
///
/// Returns an error when binding or accepting on the metrics listener fails.
pub async fn serve_metrics(port: u16, registry: Arc<Registry>) -> Result<()> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = TcpListener::bind(addr).await?;

    tracing::info!(
        "Prometheus metrics server listening on http://0.0.0.0:{}",
        port
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let registry = registry.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let registry = registry.clone();
                async move { Ok::<_, Infallible>(handle_metrics_request(&req, &registry)) }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                tracing::error!("Error serving connection: {:?}", err);
            }
        });
    }
}

fn handle_metrics_request(
    req: &Request<hyper::body::Incoming>,
    registry: &Arc<Registry>,
) -> Response<Full<Bytes>> {
    match req.uri().path() {
        "/metrics" => {
            let encoder = TextEncoder::new();
            // Merge metrics from the provided registry and the default global registry
            let mut metric_families = registry.gather();
            let mut global = prometheus::gather();
            metric_families.append(&mut global);
            let mut buffer = Vec::new();
            if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                tracing::error!("Failed to encode metrics: {e}");
                plain_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            } else {
                metrics_response(encoder.format_type(), buffer)
            }
        }
        "/health" => plain_response(StatusCode::OK, "OK"),
        _ => plain_response(StatusCode::NOT_FOUND, "Not Found"),
    }
}
