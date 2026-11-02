use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReplaceLocalAttributesRequest {
    /// Zero creates an absent local namespace; otherwise the current revision.
    #[cfg_attr(feature = "openapi", schema(minimum = 0))]
    pub base_revision: i64,
    /// Complete replacement object. An omitted member becomes missing; null is a value.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub values: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserAttributeSourceView {
    pub namespace: String,
    #[cfg_attr(feature = "openapi", schema(minimum = 1))]
    pub revision: i64,
    /// Authenticated source metadata: kind, authority, source_revision, observed_at, expires_at.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub provenance: serde_json::Value,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
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
