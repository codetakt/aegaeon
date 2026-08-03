use super::PageInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub status: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateUserRequest {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateUserRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub user_id: String,
    pub subject: String,
    pub subject_policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub email_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub custom_claims: serde_json::Value,
    pub version: i64,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateUserProfileRequest {
    pub base_version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_claims: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PasswordCredential {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    pub status: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RecoveryToken {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    pub purpose: String,
    pub status: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub redeemed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub revoked_at: Option<String>,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserCredentialsResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<PasswordCredential>,
    #[serde(default)]
    pub recovery_tokens: Vec<RecoveryToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserSessionInventoryEntry {
    pub id: String,
    pub auth_time_epoch_seconds: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListUserSessionsResponse {
    pub sessions: Vec<UserSessionInventoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserGrantInventoryEntry {
    pub id: String,
    pub source: String,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_time_epoch_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    pub expires_at_epoch_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListUserGrantsResponse {
    pub grants: Vec<UserGrantInventoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UserRefreshTokenInventoryEntry {
    pub id: String,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<serde_json::Value>,
    pub auth_time_epoch_seconds: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    pub expires_at_epoch_seconds: i64,
    pub rotation_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListUserRefreshTokensResponse {
    pub refresh_tokens: Vec<UserRefreshTokenInventoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IssueRecoveryTokenRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct IssueRecoveryTokenResponse {
    pub token: String,
    pub redeem_url: String,
    pub recovery_token: RecoveryToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InviteUserRequest {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct InviteUserResponse {
    pub user: User,
    pub activation: IssueRecoveryTokenResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ImportUsersCsvRequest {
    pub csv: String,
    #[serde(default)]
    pub issue_activation_tokens: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_token_expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ImportedUserRow {
    pub row_number: i64,
    pub user: User,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<IssueRecoveryTokenResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ImportUsersCsvResponse {
    pub imported_users: Vec<ImportedUserRow>,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
#[serde(rename_all = "camelCase")]
pub struct ListUsersQuery {
    #[serde(rename = "pageSize")]
    pub page_size: Option<u32>,
    #[serde(rename = "pageToken")]
    pub page_token: Option<String>,
    #[serde(rename = "includeDeleted")]
    pub include_deleted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListUsersResponse {
    pub users: Vec<User>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}
