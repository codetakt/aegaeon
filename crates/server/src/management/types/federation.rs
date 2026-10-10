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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_metadata_policy"
    )]
    #[cfg_attr(feature = "openapi", schema(schema_with = metadata_policy_pin_schema))]
    pub metadata_policy: Option<serde_json::Value>,
}

#[cfg(feature = "openapi")]
fn metadata_policy_pin_schema() -> utoipa::openapi::schema::Object {
    use utoipa::openapi::schema::{AdditionalProperties, ObjectBuilder, Type};

    let operators = ObjectBuilder::new()
        .schema_type(Type::Object)
        .min_properties(Some(1))
        .additional_properties(Some(AdditionalProperties::FreeForm(true)));
    let parameters = ObjectBuilder::new()
        .schema_type(Type::Object)
        .min_properties(Some(1))
        .additional_properties(Some(operators));
    ObjectBuilder::new()
        .schema_type(Type::Object)
        .min_properties(Some(1))
        .additional_properties(Some(parameters))
        .description(Some(
            "Optional local equality pin for the anchor-issued metadata policy. Omit to apply no local pin. When present, entity types, metadata parameters and operator maps must each be nonempty objects; null is invalid. Operator operands and combinations also undergo Federation policy validation, including scope token rules. This schema describes the object structure, not every semantic constraint.",
        ))
        .build()
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

// Missing means no local pin; an explicitly supplied JSON null must reach
// validation as invalid Some(null), rather than silently becoming absence.
fn present_metadata_policy<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}
