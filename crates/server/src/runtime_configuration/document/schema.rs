use crate::management::types::PolicyDocument;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ConfigurationDocumentV1 {
    pub(crate) schema_version: i64,
    pub(crate) issuer_host: String,
    pub(crate) issuer_url: String,
    pub(crate) policy: PolicyDocument,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) scope_allowlist: Vec<String>,
    pub(crate) key_store: KeyStoreDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) federation: Option<FederationDocument>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct KeyStoreDocument {
    #[serde(rename = "type")]
    pub(crate) key_store_type: String,
    pub(crate) configuration: Value,
    #[serde(default = "default_redacted")]
    pub(crate) redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FederationDocument {
    pub(crate) upstream_issuer: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) jwks_cache: Option<FederationJwksCacheDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) attribute_mapping: Vec<FederationAttributeMappingDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) claim_release: Vec<FederationClaimReleaseDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) jit_provisioning: Option<FederationJitProvisioningDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) logout: Option<FederationLogoutDocument>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FederationJwksCacheDocument {
    pub(crate) jwks_uri: String,
    pub(crate) max_age_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FederationAttributeMappingDocument {
    pub(crate) from: String,
    pub(crate) to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rule: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FederationClaimReleaseDocument {
    pub(crate) claim: String,
    pub(crate) surfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FederationJitProvisioningDocument {
    pub(crate) enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) require_verified_email: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) domain_allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) collision_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) initial_status: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct FederationLogoutDocument {
    pub(crate) back_channel: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_hint_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_policy: Option<String>,
}

pub(crate) fn parse_configuration_document_v1(
    document: &Value,
) -> Result<ConfigurationDocumentV1, serde_json::Error> {
    serde_json::from_value(document.clone())
}

pub(crate) fn parse_federation_document_value(
    federation: &Value,
) -> Result<FederationDocument, serde_json::Error> {
    serde_json::from_value(federation.clone())
}

pub(crate) fn canonical_configuration_document_v1(
    document: &Value,
) -> Result<Value, serde_json::Error> {
    let document = parse_configuration_document_v1(document)?;
    serde_json::to_value(document).map(canonicalize_json_value)
}

pub(crate) fn serialize_canonical_configuration_document_v1(
    document: &Value,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(&canonical_configuration_document_v1(document)?)
}

fn canonicalize_json_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted = map
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json_value(value)))
                .collect::<BTreeMap<_, _>>();
            let mut object = serde_json::Map::new();
            object.extend(sorted);
            Value::Object(object)
        }
        Value::Array(values) => {
            Value::Array(values.into_iter().map(canonicalize_json_value).collect())
        }
        scalar => scalar,
    }
}

const fn default_redacted() -> bool {
    true
}
