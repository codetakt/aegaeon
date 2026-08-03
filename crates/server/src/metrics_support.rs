use prometheus::{Gauge, GaugeVec, Histogram, HistogramVec, IntCounter, IntCounterVec};

pub fn metric_or_local<T, F>(
    registered: prometheus::Result<T>,
    name: &str,
    fallback: F,
) -> Option<T>
where
    F: FnOnce() -> prometheus::Result<T>,
{
    match registered {
        Ok(metric) => Some(metric),
        Err(error) => {
            tracing::warn!(
                metric = name,
                %error,
                "prometheus metric registration failed; using unregistered local metric"
            );
            fallback().map_or_else(
                |fallback_error| {
                    tracing::error!(
                        metric = name,
                        error = %fallback_error,
                        "local prometheus metric fallback unavailable"
                    );
                    None
                },
                Some,
            )
        }
    }
}

pub struct OptionalCounter {
    inner: Option<IntCounter>,
}

impl OptionalCounter {
    #[must_use]
    pub fn new(inner: Option<IntCounter>) -> Self {
        Self { inner }
    }

    pub fn inc(&self) {
        if let Some(counter) = &self.inner {
            counter.inc();
        }
    }

    pub fn inc_by(&self, value: u64) {
        if let Some(counter) = &self.inner {
            counter.inc_by(value);
        }
    }
}

pub struct OptionalCounterVec {
    inner: Option<IntCounterVec>,
}

impl OptionalCounterVec {
    #[must_use]
    pub fn new(inner: Option<IntCounterVec>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn with_label_values(&self, labels: &[&str]) -> OptionalCounter {
        OptionalCounter::new(
            self.inner
                .as_ref()
                .map(|counter| counter.with_label_values(labels)),
        )
    }
}

pub struct OptionalGauge {
    inner: Option<Gauge>,
}

impl OptionalGauge {
    #[must_use]
    pub fn new(inner: Option<Gauge>) -> Self {
        Self { inner }
    }

    pub fn set(&self, value: f64) {
        if let Some(gauge) = &self.inner {
            gauge.set(value);
        }
    }
}

pub struct OptionalGaugeVec {
    inner: Option<GaugeVec>,
}

impl OptionalGaugeVec {
    #[must_use]
    pub fn new(inner: Option<GaugeVec>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn with_label_values(&self, labels: &[&str]) -> OptionalGauge {
        OptionalGauge::new(
            self.inner
                .as_ref()
                .map(|gauge| gauge.with_label_values(labels)),
        )
    }
}

pub struct OptionalHistogram {
    inner: Option<Histogram>,
}

impl OptionalHistogram {
    #[must_use]
    pub fn new(inner: Option<Histogram>) -> Self {
        Self { inner }
    }

    pub fn observe(&self, value: f64) {
        if let Some(histogram) = &self.inner {
            histogram.observe(value);
        }
    }
}

pub struct OptionalHistogramVec {
    inner: Option<HistogramVec>,
}

impl OptionalHistogramVec {
    #[must_use]
    pub fn new(inner: Option<HistogramVec>) -> Self {
        Self { inner }
    }

    #[must_use]
    pub fn with_label_values(&self, labels: &[&str]) -> OptionalHistogram {
        OptionalHistogram::new(
            self.inner
                .as_ref()
                .map(|histogram| histogram.with_label_values(labels)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_metric_wrappers_noop_when_unavailable() {
        OptionalCounter::new(None).inc();
        OptionalCounter::new(None).inc_by(2);
        OptionalCounterVec::new(None)
            .with_label_values(&["missing"])
            .inc();
        OptionalGauge::new(None).set(1.0);
        OptionalGaugeVec::new(None)
            .with_label_values(&["missing"])
            .set(1.0);
        OptionalHistogram::new(None).observe(1.0);
        OptionalHistogramVec::new(None)
            .with_label_values(&["missing"])
            .observe(1.0);
    }

    #[test]
    fn metric_or_local_returns_none_when_registration_and_fallback_fail() {
        let registered = prometheus::IntCounter::new("invalid-name", "invalid");

        let metric = metric_or_local(registered, "invalid-name", || {
            prometheus::IntCounter::new("still invalid", "invalid")
        });

        assert!(metric.is_none());
    }
}
