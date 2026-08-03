#![allow(dead_code)] // utoipa path marker functions are referenced by OpenAPI derive metadata.
#![allow(clippy::needless_for_each)] // utoipa schema assembly favors generated-style iterator wiring.

use utoipa::OpenApi;

#[utoipa::path(
    get,
    path = "/health",
    tag = "ops",
    responses(
        (status = 200, description = "Service is healthy", body = String, content_type = "text/plain")
    )
)]
fn health() {}

#[utoipa::path(
    get,
    path = "/api/v1/operations/metrics",
    tag = "ops",
    responses(
        (status = 200, description = "Prometheus metrics for authenticated management operators", body = String, content_type = "text/plain"),
        (status = 401, description = "Management session or API key required"),
        (status = 403, description = "Metrics access requires a human session or audit-capable API key"),
        (status = 500, description = "Failed to render metrics")
    )
)]
fn metrics() {}

#[derive(OpenApi)]
#[openapi(
    paths(health, metrics),
    tags((name = "ops", description = "Operational endpoints"))
)]
pub struct OpsApiV1;
