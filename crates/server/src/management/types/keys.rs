use serde::{Deserialize, Serialize};

use super::Environment;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RuntimeKey {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    pub usage: String,
    pub kid: String,
    pub algorithm: String,
    pub provider: String,
    pub status: String,
    pub public_jwk: serde_json::Value,
    pub provider_configuration: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub retiring_expires_at: Option<String>,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RuntimeKeyMutationResponse {
    pub runtime_key: RuntimeKey,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyStoreUpdateResponse {
    pub key_store: KeyStorePublicView,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyStorePublicView {
    #[serde(rename = "type")]
    pub type_: String,
    pub configuration: serde_json::Value,
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateKeyStoreRequest {
    #[serde(rename = "type")]
    pub type_: String,
    pub configuration: serde_json::Value,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_security_downgrade: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListRuntimeKeysResponse {
    pub runtime_keys: Vec<RuntimeKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<super::PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateRuntimeKeyRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    /// Runtime key usage, such as OIDC_ID_TOKEN_SIGNING, JWT_ACCESS_TOKEN_SIGNING,
    /// or JWT_INTROSPECTION_SIGNING.
    pub usage: String,
    /// Usage-bound algorithm: RS256 for OIDC signing, RSA-OAEP+A256GCM for OIDC
    /// request-object decryption, and EdDSA for OAuth JWT signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default = "default_runtime_key_provider")]
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_configuration: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(write_only))]
    pub private_key_pem: Option<String>,
    #[serde(default)]
    pub activate: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActivateRuntimeKeyRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    pub usage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

fn default_runtime_key_provider() -> String {
    "databaseEncrypted".to_string()
}
