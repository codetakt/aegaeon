mod core;
mod jwks_cache;
mod scalar;

use axum::response::Response;
use serde_json::{Map, Value};

pub(super) fn validate_federation_core_fields(
    federation: &Map<String, Value>,
    request_id: &str,
) -> Result<(), Response> {
    core::validate_federation_core_fields(federation, request_id)
}

pub(super) fn validate_optional_jwks_cache(
    federation: &Map<String, Value>,
    request_id: &str,
) -> Result<(), Response> {
    jwks_cache::validate_optional_jwks_cache(federation, request_id)
}
