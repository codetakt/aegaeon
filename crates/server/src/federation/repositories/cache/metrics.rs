use prometheus::{register_int_counter_vec, Opts};
use std::sync::LazyLock;

use crate::metrics_support::{metric_or_local, OptionalCounterVec};

static FEDERATION_CACHE_WRITE_FAILURES: LazyLock<OptionalCounterVec> = LazyLock::new(|| {
    OptionalCounterVec::new(metric_or_local(
        register_int_counter_vec!(
            "federation_cache_write_failures_total",
            "Federation cache write failures by surface",
            &["surface"]
        ),
        "federation_cache_write_failures_total",
        || {
            prometheus::IntCounterVec::new(
                Opts::new(
                    "federation_cache_write_failures_total",
                    "Federation cache write failures by surface",
                ),
                &["surface"],
            )
        },
    ))
});

static FEDERATION_CACHE_VALIDATION_FAILURES: LazyLock<OptionalCounterVec> = LazyLock::new(|| {
    OptionalCounterVec::new(metric_or_local(
        register_int_counter_vec!(
            "federation_cache_validation_failures_total",
            "Federation cache validation failures by surface",
            &["surface"]
        ),
        "federation_cache_validation_failures_total",
        || {
            prometheus::IntCounterVec::new(
                Opts::new(
                    "federation_cache_validation_failures_total",
                    "Federation cache validation failures by surface",
                ),
                &["surface"],
            )
        },
    ))
});

pub(super) fn record_federation_cache_write_failure(surface: &'static str) {
    FEDERATION_CACHE_WRITE_FAILURES
        .with_label_values(&[surface])
        .inc();
}

pub(super) fn record_federation_cache_validation_failure(surface: &'static str) {
    FEDERATION_CACHE_VALIDATION_FAILURES
        .with_label_values(&[surface])
        .inc();
}
