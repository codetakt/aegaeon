use super::fixture::*;
use crate::metrics_integration::MetricsIntegration;
use crate::web::test_support::TestResult;
use axum::body::Body;
use std::sync::Arc;

fn sample(reason: &str, method: &str) -> TestResult<(f64, f64, u64)> {
    MetricsIntegration::with_global(|integration| {
        (
            integration
                .metrics
                .resource_requests
                .with_label_values(&["bearer", reason])
                .get(),
            integration
                .metrics
                .token_operations
                .with_label_values(&["resource_access", "bearer"])
                .get(),
            integration
                .metrics
                .request_latency
                .with_label_values(&["/resource", method])
                .get_sample_count(),
        )
    })
    .ok_or_else(|| "fixture metrics missing".into())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB and serial global metrics observations"]
async fn resource_authentication_early_classification_preserves_failure_and_latency_metrics(
) -> TestResult {
    let fixture = Fixture::new().await?;
    let integration = Arc::new(MetricsIntegration::new(Arc::new(
        aegaeon_observability::metrics::OAuthMetrics::new(&prometheus::Registry::new())?,
    )));
    MetricsIntegration::register_global(&integration);
    let result = async {
        for (auth, reason) in [
            (None, "authorization header required"),
            (Some(" "), "malformed authorization header"),
            (
                Some("Unknown credentials"),
                "authorization scheme must be Bearer or DPoP",
            ),
            (Some("Bearer"), "malformed authorization header"),
            (Some("DPoP"), "malformed authorization header"),
        ] {
            for method in ["GET", "HEAD"] {
                let before = sample(reason, method)?;
                let response = request(
                    &fixture.state,
                    method,
                    "/resource",
                    headers(auth, Some("unvalidated-proof"), false)?,
                    Body::empty(),
                )
                .await?;
                assert!(response.status().is_client_error());
                let after = sample(reason, method)?;
                assert_eq!(after, (before.0 + 1.0, before.1 + 1.0, before.2 + 1));
            }
        }
        assert_eq!(fixture.replay.attempts(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}
