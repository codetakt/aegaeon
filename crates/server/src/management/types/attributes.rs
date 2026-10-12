use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplaceLocalAttributesRequest {
    /// Zero creates an absent local namespace; otherwise the current revision.
    pub base_revision: i64,
    /// Complete replacement object. An omitted member becomes missing; null is a value.
    pub values: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserAttributeSourceView {
    pub namespace: String,
    pub revision: i64,
    /// Authenticated source metadata: kind, authority, source_revision, observed_at, expires_at.
    pub provenance: serde_json::Value,
    pub values: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserAttributeSourcesResponse {
    pub user_id: String,
    pub sources: Vec<UserAttributeSourceView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct LocalAttributesResponse {
    pub user_id: String,
    pub source: UserAttributeSourceView,
}
