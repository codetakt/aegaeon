use axum::http::{header, HeaderValue, Method};
use tower_http::cors::CorsLayer;

use crate::web::management::{ManagementConfig, ManagementState};

pub(in crate::web::management) fn build_management_cors_layer(mgmt: &ManagementState) -> CorsLayer {
    let allowed_headers = [
        header::CONTENT_TYPE,
        header::HeaderName::from_static("x-csrf-token"),
    ];
    let allowed_methods = [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ];

    let mut cors = CorsLayer::new()
        .allow_methods(allowed_methods)
        .allow_headers(allowed_headers);

    match management_cors_allowed_origins(&mgmt.cfg) {
        Ok(Some(origins)) => {
            cors = cors.allow_origin(origins).allow_credentials(true);
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(
                error = %err,
                "management CORS origin state is invalid; CORS allowlist disabled"
            );
        }
    }

    cors
}

pub(in crate::web::management) fn management_cors_allowed_origins(
    cfg: &ManagementConfig,
) -> Result<Option<Vec<HeaderValue>>, String> {
    if cfg.allowed_origins.is_empty() {
        return Ok(None);
    }
    cfg.allowed_origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin)
                .map_err(|err| format!("invalid management origin {origin:?}: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}
