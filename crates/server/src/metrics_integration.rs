use aegaeon_observability::metrics::OAuthMetrics;
use prometheus::{register_histogram, register_int_counter};
use std::sync::{Arc, OnceLock};
use tokio::time::{interval, Duration};

use crate::metrics_support::{metric_or_local, OptionalCounter, OptionalHistogram};

/// OAuth metrics integration for server flows
pub struct MetricsIntegration {
    pub metrics: Arc<OAuthMetrics>,
}

static GLOBAL_INTEGRATION: OnceLock<Arc<MetricsIntegration>> = OnceLock::new();

fn int_counter_metric(name: &str, help: &str) -> OptionalCounter {
    OptionalCounter::new(metric_or_local(
        register_int_counter!(name, help),
        name,
        || prometheus::IntCounter::with_opts(prometheus::Opts::new(name, help)),
    ))
}

fn histogram_metric(name: &str, help: &str, buckets: Vec<f64>) -> OptionalHistogram {
    OptionalHistogram::new(metric_or_local(
        register_histogram!(name, help, buckets.clone()),
        name,
        || {
            prometheus::Histogram::with_opts(
                prometheus::HistogramOpts::new(name, help).buckets(buckets),
            )
        },
    ))
}

static REFRESH_BINDINGS_TOTAL: std::sync::LazyLock<OptionalCounter> =
    std::sync::LazyLock::new(|| {
        int_counter_metric(
            "oauth_refresh_token_bindings_total",
            "Number of access tokens bound to refresh tokens",
        )
    });
static REFRESH_ROTATION_CONFLICTS: std::sync::LazyLock<OptionalCounter> =
    std::sync::LazyLock::new(|| {
        int_counter_metric(
            "oauth_refresh_token_rotation_conflicts_total",
            "Count of refresh tokens reused after rotation",
        )
    });
static REFRESH_CASCADE_REVOKED: std::sync::LazyLock<OptionalCounter> =
    std::sync::LazyLock::new(|| {
        int_counter_metric(
            "oauth_refresh_cascade_revoked_total",
            "Total number of access tokens revoked via refresh-token cascade",
        )
    });
static REFRESH_CASCADE_SIZE: std::sync::LazyLock<OptionalHistogram> =
    std::sync::LazyLock::new(|| {
        histogram_metric(
            "oauth_refresh_cascade_size",
            "Distribution of cascade revocation set size",
            vec![1.0, 2.0, 5.0, 10.0, 20.0],
        )
    });

impl MetricsIntegration {
    #[must_use]
    pub fn new(metrics: Arc<OAuthMetrics>) -> Self {
        Self { metrics }
    }

    /// Register this instance so lower layers can publish metrics without plumbing references.
    pub fn register_global(instance: &Arc<MetricsIntegration>) {
        let _ = GLOBAL_INTEGRATION.set(Arc::clone(instance));
    }

    pub fn with_global<F, R>(f: F) -> Option<R>
    where
        F: FnOnce(&MetricsIntegration) -> R,
    {
        GLOBAL_INTEGRATION.get().map(|instance| f(instance))
    }

    /// Start background task to update rate metrics
    pub fn start_metrics_updater(metrics: Arc<OAuthMetrics>) {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));

            loop {
                interval.tick().await;
                metrics.update_rate_metrics();
            }
        });
    }

    /// Record `DPoP` validation attempt
    pub fn record_dpop_validation(&self, success: bool, reason: Option<&str>) {
        // Note: Don't increment token_operations here as it's already done
        // in the endpoint handlers when we know the actual token type

        if !success {
            let failure_reason = reason.unwrap_or("unknown");
            self.metrics.record_dpop_failure(failure_reason);
        }
    }

    /// Record `DPoP` validation attempt with token type
    pub fn record_dpop_validation_with_type(
        &self,
        token_type: &str,
        success: bool,
        reason: Option<&str>,
    ) {
        self.metrics
            .token_operations
            .with_label_values(&["dpop_bound", token_type])
            .inc();

        if !success {
            let failure_reason = reason.unwrap_or("unknown");
            self.metrics.record_dpop_failure(failure_reason);
        }
    }

    /// Record PKCE verification attempt
    pub fn record_pkce_verification(&self, client_id: &str, success: bool) {
        // Only record PKCE-specific metrics, not auth attempts
        // Auth attempts are tracked separately in the token endpoint
        if !success {
            self.metrics.record_pkce_mismatch(client_id);
        }
    }

    /// Record PAR request
    pub fn record_par_request(&self, client_id: &str, success: bool) {
        self.metrics.record_par_request(client_id, success);
    }

    /// Record token introspection
    pub fn record_introspection(&self, token_type: &str, active: bool) {
        self.metrics.record_introspection(token_type, active);
    }

    /// Record token revocation
    pub fn record_revocation(&self, token_type: &str, success: bool) {
        self.metrics.record_revocation(token_type, success);
    }

    /// Record authorization attempt
    pub fn record_auth_attempt(&self, grant_type: &str, client_id: &str, success: bool) {
        // Record for specific client
        self.metrics
            .record_auth_attempt(grant_type, client_id, success);
        // Also record for "all" to track total attempts
        self.metrics.record_auth_attempt(grant_type, "all", success);
    }

    /// Record resource endpoint access outcome
    pub fn record_resource_access(&self, mode: &str, success: bool, reason: Option<&str>) {
        self.metrics
            .token_operations
            .with_label_values(&["resource_access", mode])
            .inc();

        let status = if success {
            "success".to_string()
        } else {
            reason.unwrap_or("failure").to_string()
        };

        self.metrics
            .resource_requests
            .with_label_values(&[mode, &status])
            .inc();

        if !success && mode == "dpop" {
            self.metrics
                .record_dpop_failure(reason.unwrap_or("unknown"));
        }
    }

    pub fn record_sender_binding_failure(&self, reason: &str) {
        self.metrics.record_sender_binding_failure(reason);
    }

    pub fn record_refresh_policy_violation(&self, reason: &str) {
        self.metrics.record_refresh_policy_violation(reason);
    }

    pub fn record_stepup_event(&self, event: &str) {
        self.metrics.record_stepup_event(event);
    }

    pub fn record_oauth_profile_operation(&self, operation: &str, status: &str) {
        self.metrics
            .record_oauth_profile_operation(operation, status);
    }

    pub fn record_oauth_profile_usage(&self, profile_type: &str, endpoint: &str) {
        self.metrics
            .record_oauth_profile_usage(profile_type, endpoint);
    }

    pub fn record_oauth_profile_rejection(&self, profile_type: &str, reason: &str, endpoint: &str) {
        self.metrics
            .record_oauth_profile_rejection(profile_type, reason, endpoint);
    }

    pub fn record_refresh_binding(&self) {
        REFRESH_BINDINGS_TOTAL.inc();
    }

    pub fn record_refresh_rotation_conflict(&self) {
        REFRESH_ROTATION_CONFLICTS.inc();
    }

    pub fn record_refresh_cascade(&self, revoked_children: usize) {
        if revoked_children > 0 {
            REFRESH_CASCADE_REVOKED.inc_by(revoked_children as u64);
            let bucket_value = match u32::try_from(revoked_children) {
                Ok(value) => f64::from(value),
                Err(_) => f64::from(u32::MAX),
            };
            REFRESH_CASCADE_SIZE.observe(bucket_value);
        }
    }
}
