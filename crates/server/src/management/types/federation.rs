use super::PageInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationTrustAnchor {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    pub entity_id: String,
    pub jwks: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<serde_json::Value>,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateFederationTrustAnchorRequest {
    pub entity_id: String,
    pub jwks: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListFederationTrustAnchorsResponse {
    pub trust_anchors: Vec<FederationTrustAnchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationEntityCacheEntry {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    pub entity_id: String,
    pub entity_configuration_jws: String,
    pub parsed_statement: serde_json::Value,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub fetched_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListFederationEntityCacheResponse {
    pub entity_cache_entries: Vec<FederationEntityCacheEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationTrustChainEntry {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    pub leaf_entity_id: String,
    pub anchor_entity_id: String,
    pub chain_jwts: serde_json::Value,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub resolved_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListFederationTrustChainsResponse {
    pub trust_chains: Vec<FederationTrustChainEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FederationLogoutRecoveryIncident {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub team_id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub tenant_id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downstream_client_id: Option<String>,
    pub upstream_issuer: String,
    pub recovery_policy: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_hint_claim: Option<String>,
    pub session_hint_present: bool,
    pub downstream_redirect_uri: String,
    pub downstream_state_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub request_id: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListFederationLogoutRecoveryIncidentsResponse {
    pub incidents: Vec<FederationLogoutRecoveryIncident>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClearFederationLogoutRecoveryIncidentRequest {
    pub reason: String,
}
