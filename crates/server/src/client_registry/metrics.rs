use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use prometheus::{register_gauge_vec, register_int_counter, register_int_counter_vec};

use super::JwksRuntimePolicy;
use crate::metrics_support::{
    metric_or_local, OptionalCounter, OptionalCounterVec, OptionalGaugeVec, OptionalHistogramVec,
};

fn int_counter_metric(
    result: prometheus::Result<prometheus::IntCounter>,
    name: &str,
    help: &str,
) -> OptionalCounter {
    OptionalCounter::new(metric_or_local(result, name, || {
        prometheus::IntCounter::new(name, help)
    }))
}

fn int_counter_vec_metric(
    result: prometheus::Result<prometheus::IntCounterVec>,
    name: &str,
    help: &str,
    labels: &[&str],
) -> OptionalCounterVec {
    OptionalCounterVec::new(metric_or_local(result, name, || {
        prometheus::IntCounterVec::new(prometheus::Opts::new(name, help), labels)
    }))
}

fn gauge_vec_metric(
    result: prometheus::Result<prometheus::GaugeVec>,
    name: &str,
    help: &str,
    labels: &[&str],
) -> OptionalGaugeVec {
    OptionalGaugeVec::new(metric_or_local(result, name, || {
        prometheus::GaugeVec::new(prometheus::Opts::new(name, help), labels)
    }))
}

fn histogram_vec_metric(
    result: prometheus::Result<prometheus::HistogramVec>,
    name: &str,
    policy: &JwksRuntimePolicy,
    labels: &[&str],
) -> OptionalHistogramVec {
    OptionalHistogramVec::new(metric_or_local(result, name, || {
        prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(name, "JWKS HTTP fetch latency")
                .buckets(policy.histogram_buckets.clone()),
            labels,
        )
    }))
}

static JWKS_CACHE_HIT_MEMORY: LazyLock<OptionalCounter> = LazyLock::new(|| {
    int_counter_metric(
        register_int_counter!("jwks_cache_hit_memory_total", "JWKS memory cache hits"),
        "jwks_cache_hit_memory_total",
        "JWKS memory cache hits",
    )
});

static JWKS_HTTP_304: LazyLock<OptionalCounter> = LazyLock::new(|| {
    int_counter_metric(
        register_int_counter!(
            "jwks_http_304_total",
            "JWKS HTTP 304 Not Modified responses"
        ),
        "jwks_http_304_total",
        "JWKS HTTP 304 Not Modified responses",
    )
});

static JWKS_HTTP_SUCCESS: LazyLock<OptionalCounter> = LazyLock::new(|| {
    int_counter_metric(
        register_int_counter!("jwks_http_success_total", "JWKS HTTP 2xx success responses"),
        "jwks_http_success_total",
        "JWKS HTTP 2xx success responses",
    )
});

static JWKS_HTTP_FAILURES: LazyLock<OptionalCounter> = LazyLock::new(|| {
    int_counter_metric(
        register_int_counter!(
            "jwks_http_failure_total",
            "JWKS HTTP failure or retry exhausted"
        ),
        "jwks_http_failure_total",
        "JWKS HTTP failure or retry exhausted",
    )
});

static JWKS_KID_DUPLICATE: LazyLock<OptionalCounter> = LazyLock::new(|| {
    int_counter_metric(
        register_int_counter!(
            "jwks_kid_duplicate_total",
            "JWKS documents with duplicate kid values"
        ),
        "jwks_kid_duplicate_total",
        "JWKS documents with duplicate kid values",
    )
});

static JWKS_KID_REUSE_VIOLATIONS: LazyLock<OptionalCounter> = LazyLock::new(|| {
    int_counter_metric(
        register_int_counter!(
            "jwks_kid_reuse_violations_total",
            "Kid reused with different material across updates"
        ),
        "jwks_kid_reuse_violations_total",
        "Kid reused with different material across updates",
    )
});

static JWKS_HTTP_EVENTS: LazyLock<OptionalCounterVec> = LazyLock::new(|| {
    int_counter_vec_metric(
        register_int_counter_vec!(
            "jwks_http_events_total",
            "JWKS HTTP events by outcome and uri hash",
            &["outcome", "uri_hash"]
        ),
        "jwks_http_events_total",
        "JWKS HTTP events by outcome and uri hash",
        &["outcome", "uri_hash"],
    )
});

static JWKS_HTTP_LATENCY: OnceLock<OptionalHistogramVec> = OnceLock::new();

fn jwks_http_latency(policy: &JwksRuntimePolicy) -> &'static OptionalHistogramVec {
    JWKS_HTTP_LATENCY.get_or_init(|| {
        histogram_vec_metric(
            prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "jwks_http_latency_seconds",
                    "JWKS HTTP fetch latency",
                )
                .buckets(policy.histogram_buckets.clone()),
                &["outcome", "uri_hash"],
            ),
            "jwks_http_latency_seconds",
            policy,
            &["outcome", "uri_hash"],
        )
    })
}

static JWKS_HTTP_FAILURES_REASON: LazyLock<OptionalCounterVec> = LazyLock::new(|| {
    int_counter_vec_metric(
        register_int_counter_vec!(
            "jwks_http_failures_reason_total",
            "JWKS HTTP failure reasons by reason and uri hash",
            &["reason", "uri_hash"]
        ),
        "jwks_http_failures_reason_total",
        "JWKS HTTP failure reasons by reason and uri hash",
        &["reason", "uri_hash"],
    )
});

static JWKS_CIRCUIT_STATE: LazyLock<OptionalGaugeVec> = LazyLock::new(|| {
    gauge_vec_metric(
        register_gauge_vec!(
            "jwks_circuit_state",
            "JWKS circuit state gauge (1=current state, labeled by state and uri hash)",
            &["state", "uri_hash"]
        ),
        "jwks_circuit_state",
        "JWKS circuit state gauge (1=current state, labeled by state and uri hash)",
        &["state", "uri_hash"],
    )
});

static JWKS_SHARED_RUNTIME_STATE_FAILURES: LazyLock<OptionalCounterVec> = LazyLock::new(|| {
    int_counter_vec_metric(
        register_int_counter_vec!(
            "jwks_shared_runtime_state_failures_total",
            "JWKS shared runtime state failures by operation and uri hash",
            &["operation", "uri_hash"]
        ),
        "jwks_shared_runtime_state_failures_total",
        "JWKS shared runtime state failures by operation and uri hash",
        &["operation", "uri_hash"],
    )
});

static RUNTIME_BCP_NONCOMPLIANT: LazyLock<OptionalCounterVec> = LazyLock::new(|| {
    int_counter_vec_metric(
        register_int_counter_vec!(
            "runtime_bcp_noncompliant_total",
            "Runtime BCP noncompliance (client assertion) by reason",
            &["reason"]
        ),
        "runtime_bcp_noncompliant_total",
        "Runtime BCP noncompliance (client assertion) by reason",
        &["reason"],
    )
});

pub(super) fn record_runtime_bcp_noncompliant(reason: &'static str) {
    RUNTIME_BCP_NONCOMPLIANT.with_label_values(&[reason]).inc();
}

pub(super) fn record_jwks_cache_hit_memory() {
    JWKS_CACHE_HIT_MEMORY.inc();
}

pub(super) fn record_jwks_http_event(outcome: &str, uri_hash: &str) {
    JWKS_HTTP_EVENTS
        .with_label_values(&[outcome, uri_hash])
        .inc();
}

pub(super) fn record_jwks_http_failure() {
    JWKS_HTTP_FAILURES.inc();
}

pub(super) fn record_jwks_http_failure_reason(reason: &str, uri_hash: &str) {
    JWKS_HTTP_FAILURES_REASON
        .with_label_values(&[reason, uri_hash])
        .inc();
}

fn observe_jwks_http_latency(
    policy: &JwksRuntimePolicy,
    outcome: &str,
    uri_hash: &str,
    elapsed: Duration,
) {
    jwks_http_latency(policy)
        .with_label_values(&[outcome, uri_hash])
        .observe(elapsed.as_secs_f64());
}

pub(super) fn record_jwks_http_not_modified(
    policy: &JwksRuntimePolicy,
    uri_hash: &str,
    elapsed: Duration,
) {
    JWKS_HTTP_304.inc();
    record_jwks_http_event("304", uri_hash);
    observe_jwks_http_latency(policy, "304", uri_hash, elapsed);
}

pub(super) fn record_jwks_http_success(
    policy: &JwksRuntimePolicy,
    uri_hash: &str,
    elapsed: Duration,
) {
    JWKS_HTTP_SUCCESS.inc();
    record_jwks_http_event("200", uri_hash);
    observe_jwks_http_latency(policy, "200", uri_hash, elapsed);
}

pub(super) fn record_jwks_http_status_failure(
    policy: &JwksRuntimePolicy,
    uri_hash: &str,
    status: &str,
    reason: &str,
    elapsed: Duration,
) {
    record_jwks_http_failure();
    record_jwks_http_event(status, uri_hash);
    observe_jwks_http_latency(policy, status, uri_hash, elapsed);
    record_jwks_http_failure_reason(reason, uri_hash);
}

pub(super) fn record_jwks_http_error(
    policy: &JwksRuntimePolicy,
    uri_hash: &str,
    reason: &str,
    elapsed: Duration,
) {
    record_jwks_http_status_failure(policy, uri_hash, "error", reason, elapsed);
}

pub(super) fn record_jwks_kid_duplicate() {
    JWKS_KID_DUPLICATE.inc();
}

pub(super) fn record_jwks_kid_reuse_violation() {
    JWKS_KID_REUSE_VIOLATIONS.inc();
}

pub(super) fn set_jwks_circuit_state(uri_hash: &str, active_state: &str) {
    for state in ["open", "half_open", "closed"] {
        let value = if state == active_state { 1.0 } else { 0.0 };
        JWKS_CIRCUIT_STATE
            .with_label_values(&[state, uri_hash])
            .set(value);
    }
}

pub(super) fn record_jwks_shared_runtime_state_failure(operation: &'static str, uri_hash: &str) {
    JWKS_SHARED_RUNTIME_STATE_FAILURES
        .with_label_values(&[operation, uri_hash])
        .inc();
}
