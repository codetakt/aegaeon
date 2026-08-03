use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(
    feature = "openapi",
    schema(
        description = "Error envelope for management APIs. Common `errorCode` values include `invalid_request`, `not_found`, `forbidden`, `base_version_mismatch`, and `SECURITY_LEDGER_CONFLICT`."
    )
)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error_code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}
