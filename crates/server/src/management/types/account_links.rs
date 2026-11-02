use super::{PageInfo, User};
use serde::{Deserialize, Serialize};

/// Local source of binding authority; not proof of historical ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountLinkProvenance {
    LegacyUnreviewed,
    JitV2,
    AdministratorConfirmed,
}

impl AccountLinkProvenance {
    pub(crate) fn from_database(value: &str) -> Option<Self> {
        match value {
            "legacy_unreviewed" => Some(Self::LegacyUnreviewed),
            "jit_v2" => Some(Self::JitV2),
            "administrator_confirmed" => Some(Self::AdministratorConfirmed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkSummary {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub connection_id: String,
    pub connection_identifier: String,
    pub connection_name: String,
    pub upstream_issuer: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub end_user_id: String,
    pub end_user_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_user_email: Option<String>,
    pub end_user_status: String,
    pub has_refresh_token: bool,
    pub binding_provenance: AccountLinkProvenance,
    /// Positive revision, advanced only when the binding owner changes.
    #[cfg_attr(feature = "openapi", schema(minimum = 1))]
    pub binding_revision: i64,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListAccountLinksResponse {
    pub account_links: Vec<AccountLinkSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateAccountLinkRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub connection_id: String,
    pub upstream_subject: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub end_user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PreviewAccountLinkConflictRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub connection_id: String,
    pub upstream_subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResolveAccountLinkConflictRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub connection_id: String,
    pub upstream_subject: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub end_user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_refresh_token_handling: Option<AccountLinkRefreshTokenHandling>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_confidence_handling: Option<AccountLinkLowConfidenceHandling>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactive_target_handling: Option<AccountLinkInactiveTargetHandling>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountLinkRefreshTokenHandling {
    Clear,
    Retain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountLinkLowConfidenceHandling {
    AllowLowConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountLinkInactiveTargetHandling {
    AllowInactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkConflictCandidate {
    pub end_user: User,
    pub match_reasons: Vec<String>,
    pub recommended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkConflictPreview {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub requested_connection_id: String,
    pub requested_connection_identifier: String,
    pub requested_connection_name: String,
    pub upstream_issuer: String,
    pub upstream_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_account_link: Option<AccountLinkSummary>,
    #[serde(default)]
    pub candidate_end_users: Vec<AccountLinkConflictCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelinkAccountLinkRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub end_user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_refresh_token_handling: Option<AccountLinkRefreshTokenHandling>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactive_target_handling: Option<AccountLinkInactiveTargetHandling>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BulkRelinkAccountLinksRequest {
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "uuid"))]
    pub account_link_ids: Vec<String>,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub end_user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_refresh_token_handling: Option<AccountLinkRefreshTokenHandling>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inactive_target_handling: Option<AccountLinkInactiveTargetHandling>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct BulkRelinkAccountLinksResponse {
    pub account_links: Vec<AccountLinkSummary>,
}
