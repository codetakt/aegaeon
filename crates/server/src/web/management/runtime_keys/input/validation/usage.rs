use axum::response::Response;

use super::super::types::RuntimeKeyUsageInput;
use super::error::runtime_key_bad_request;

pub(in crate::web::management) fn parse_runtime_key_usage(
    value: &str,
    request_id: &str,
) -> Result<RuntimeKeyUsageInput, Response> {
    match value.trim() {
        "OIDC_ID_TOKEN_SIGNING" => Ok(RuntimeKeyUsageInput::OidcIdTokenSigning),
        "OIDC_REQUEST_OBJECT_DECRYPTION" => Ok(RuntimeKeyUsageInput::OidcRequestObjectDecryption),
        "JWT_ACCESS_TOKEN_SIGNING" => Ok(RuntimeKeyUsageInput::JwtAccessTokenSigning),
        "JWT_INTROSPECTION_SIGNING" => Ok(RuntimeKeyUsageInput::JwtIntrospectionSigning),
        _ => Err(runtime_key_bad_request(
            request_id,
            "Unsupported runtime key usage",
            Some(serde_json::json!({
                "supportedUsages": [
                    "OIDC_ID_TOKEN_SIGNING",
                    "OIDC_REQUEST_OBJECT_DECRYPTION",
                    "JWT_ACCESS_TOKEN_SIGNING",
                    "JWT_INTROSPECTION_SIGNING"
                ],
            })),
        )),
    }
}
