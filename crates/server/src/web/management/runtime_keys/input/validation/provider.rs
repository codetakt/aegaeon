use axum::response::Response;
use serde::Deserialize;

use crate::web::management::generate_random_kid;
use crate::web::management::key_stores::key_store_public_config_contains_sensitive_key;

use super::error::runtime_key_bad_request;

pub(in crate::web::management::runtime_keys::input) fn normalize_runtime_key_provider(
    value: &str,
    request_id: &str,
) -> Result<String, Response> {
    let provider = value.trim();
    if matches!(provider, "databaseEncrypted" | "awsKms") {
        return Ok(provider.to_string());
    }

    Err(runtime_key_bad_request(
        request_id,
        "Unsupported runtime key provider",
        Some(serde_json::json!({
            "supportedProviders": ["databaseEncrypted", "awsKms"],
        })),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AwsKmsProviderConfiguration {
    region: String,
    key_id: String,
}

#[derive(Debug)]
pub(in crate::web::management::runtime_keys::input) struct NormalizedAwsKmsProviderConfiguration {
    pub(in crate::web::management::runtime_keys::input) region: String,
    pub(in crate::web::management::runtime_keys::input) key_id: String,
}

pub(in crate::web::management::runtime_keys::input) fn normalize_aws_kms_provider_configuration(
    configuration: Option<&serde_json::Value>,
    request_id: &str,
) -> Result<NormalizedAwsKmsProviderConfiguration, Response> {
    let Some(configuration) = configuration else {
        return Err(runtime_key_bad_request(
            request_id,
            "providerConfiguration is required for awsKms runtime keys",
            None,
        ));
    };
    let parsed: AwsKmsProviderConfiguration = serde_json::from_value(configuration.clone())
        .map_err(|_| {
            runtime_key_bad_request(
                request_id,
                "providerConfiguration for awsKms must contain region and keyId only",
                None,
            )
        })?;
    let region = parsed.region.trim();
    let key_id = parsed.key_id.trim();
    if region.is_empty() || key_id.is_empty() {
        return Err(runtime_key_bad_request(
            request_id,
            "awsKms providerConfiguration region and keyId must not be empty",
            None,
        ));
    }
    Ok(NormalizedAwsKmsProviderConfiguration {
        region: region.to_string(),
        key_id: key_id.to_string(),
    })
}

pub(in crate::web::management::runtime_keys::input) fn normalize_runtime_key_kid(
    kid: Option<&str>,
    request_id: &str,
) -> Result<String, Response> {
    match kid {
        Some(raw) if raw.trim().is_empty() => Err(runtime_key_bad_request(
            request_id,
            "kid must not be empty",
            None,
        )),
        Some(raw) => Ok(raw.trim().to_string()),
        None => Ok(generate_random_kid()),
    }
}

pub(in crate::web::management::runtime_keys::input) fn normalize_runtime_key_provider_configuration(
    provider: &str,
    configuration: Option<&serde_json::Value>,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let configuration = configuration
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    if !configuration.is_object() {
        return Err(runtime_key_bad_request(
            request_id,
            "providerConfiguration must be a JSON object",
            None,
        ));
    }
    if key_store_public_config_contains_sensitive_key(&configuration) {
        return Err(runtime_key_bad_request(
            request_id,
            "providerConfiguration must not contain secret material",
            None,
        ));
    }
    if provider == "databaseEncrypted"
        && configuration.as_object().is_some_and(|map| !map.is_empty())
    {
        return Err(runtime_key_bad_request(
            request_id,
            "databaseEncrypted runtime keys do not accept providerConfiguration",
            None,
        ));
    }

    Ok(configuration)
}
