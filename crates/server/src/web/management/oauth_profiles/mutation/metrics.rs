use crate::metrics_integration::MetricsIntegration;

pub(super) fn record_oauth_profile_metric(operation: &str, outcome: &str) {
    MetricsIntegration::with_global(|metrics| {
        metrics.record_oauth_profile_operation(operation, outcome);
    });
}
