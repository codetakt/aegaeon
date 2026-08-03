use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateSessionRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BootstrapOwnerRequest {
    pub email: String,
    pub password: String,
    /// Optional bootstrap token for first-owner creation.
    ///
    /// When the server is configured with `AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN`, this field becomes
    /// required and MUST match that value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_token: Option<String>,
}
