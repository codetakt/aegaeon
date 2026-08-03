use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub enum ApiKeyCapability {
    Read,
    AuditRead,
    TeamAdministration,
}

impl ApiKeyCapability {
    #[must_use]
    pub fn as_db_value(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::AuditRead => "AUDIT_READ",
            Self::TeamAdministration => "TEAM_ADMINISTRATION",
        }
    }

    #[must_use]
    pub fn from_db_value(value: &str) -> Option<Self> {
        match value {
            "READ" => Some(Self::Read),
            "AUDIT_READ" => Some(Self::AuditRead),
            "TEAM_ADMINISTRATION" => Some(Self::TeamAdministration),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub team_id: String,
    pub name: String,
    pub key_prefix: String,
    pub capabilities: Vec<ApiKeyCapability>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub expires_at: Option<String>,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub capabilities: Vec<ApiKeyCapability>,
    /// Expiration in days from now. If omitted, the control-plane policy default is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<u32>,
    /// Explicitly request a non-expiring key. Rejected unless the control-plane policy allows it.
    #[serde(default)]
    pub never_expires: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyResponse {
    /// The raw API key value. Only returned at creation time; cannot be retrieved again.
    pub api_key_value: String,
    pub api_key: ApiKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListApiKeysResponse {
    pub api_keys: Vec<ApiKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<super::PageInfo>,
}
