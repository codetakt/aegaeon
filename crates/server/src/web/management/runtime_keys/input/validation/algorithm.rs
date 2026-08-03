use axum::response::Response;

use super::super::types::RuntimeKeyUsageInput;
use super::error::runtime_key_bad_request;

pub(in crate::web::management::runtime_keys::input) fn normalize_runtime_key_algorithm(
    usage: RuntimeKeyUsageInput,
    algorithm: Option<&str>,
    request_id: &str,
) -> Result<String, Response> {
    let algorithm = algorithm
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| usage.default_algorithm());
    let canonical = match algorithm.to_ascii_uppercase().as_str() {
        "EDDSA" => "EdDSA",
        "RS256" => "RS256",
        "RSA-OAEP+A256GCM" => "RSA-OAEP+A256GCM",
        _ => algorithm,
    };
    if usage.supported_algorithms().contains(&canonical) {
        return Ok(canonical.to_string());
    }

    Err(runtime_key_bad_request(
        request_id,
        "Unsupported algorithm for runtime key usage",
        Some(serde_json::json!({
            "usage": usage.as_db_str(),
            "supportedAlgorithms": usage.supported_algorithms(),
        })),
    ))
}
