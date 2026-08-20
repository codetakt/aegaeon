use super::super::required_row_value;
use crate::management::types::RuntimeKey;
use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

pub(in crate::web::management) fn runtime_key_from_row(
    row: &PgRow,
    request_id: &str,
) -> Result<RuntimeKey, Response> {
    let message = "Failed to load runtime key";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let usage: String = required_row_value(row, "usage", request_id, message)?;
    let kid: String = required_row_value(row, "kid", request_id, message)?;
    let algorithm: String = required_row_value(row, "algorithm", request_id, message)?;
    let provider: String = required_row_value(row, "provider", request_id, message)?;
    let status: String = required_row_value(row, "status", request_id, message)?;
    let public_jwk: serde_json::Value = required_row_value(row, "public_jwk", request_id, message)?;
    let raw_provider_configuration: serde_json::Value =
        required_row_value(row, "provider_configuration", request_id, message)?;
    let retiring_expires_at: Option<String> =
        required_row_value(row, "retiring_expires_at", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let provider_configuration =
        public_runtime_key_provider_configuration(&provider, &raw_provider_configuration);

    Ok(RuntimeKey {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        usage,
        kid,
        algorithm,
        provider,
        status,
        public_jwk,
        provider_configuration,
        retiring_expires_at,
        created_at,
    })
}

fn public_runtime_key_provider_configuration(
    provider: &str,
    configuration: &serde_json::Value,
) -> serde_json::Value {
    match provider {
        "awsKms" => configuration
            .get("region")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|region| !region.is_empty())
            .map_or_else(
                || serde_json::json!({}),
                |region| serde_json::json!({ "region": region }),
            ),
        _ => serde_json::json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::public_runtime_key_provider_configuration;
    use serde_json::json;

    #[test]
    fn public_provider_configuration_redacts_database_encrypted() {
        let public = public_runtime_key_provider_configuration(
            "databaseEncrypted",
            &json!({ "keyHandle": "secret", "region": "unused" }),
        );

        assert_eq!(public, json!({}));
    }

    #[test]
    fn public_provider_configuration_allows_aws_region_only() {
        let public = public_runtime_key_provider_configuration(
            "awsKms",
            &json!({ "region": "ap-northeast-1", "keyId": "secret" }),
        );

        assert_eq!(public, json!({ "region": "ap-northeast-1" }));
    }
}
