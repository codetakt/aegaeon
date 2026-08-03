use super::{Environment, PageInfo};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct Client {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub oauth_profile_id: Option<String>,
    pub client_identifier: String,
    pub name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub token_endpoint_authentication_method: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateClientRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub oauth_profile_id: Option<String>,
    pub name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_grant_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_authentication_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateClientRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub oauth_profile_id: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_grant_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_authentication_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub configuration_version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub oauth_profile_id: Option<String>,
    pub connection_identifier: String,
    pub name: String,
    pub connection_type: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_auth_method: String,
    pub status: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CreateConnectionRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    pub connection_identifier: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<String>,
    pub issuer_url: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub oauth_profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateConnectionRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub oauth_profile_id: Option<Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Operator-facing policy documents keep individual toggles explicit.
pub struct OAuthProfile {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub environment_id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub configuration_version_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub profile_type: String,
    pub is_default: bool,
    pub require_pkce: bool,
    pub require_state_parameter: bool,
    pub require_iss_parameter: bool,
    pub sender_constrained: String,
    pub enforce_refresh_sender_binding: bool,
    pub allowed_grant_types: Vec<String>,
    pub token_endpoint_auth_methods_allowed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub expires_at: Option<String>,
    pub status: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Request payload mirrors the explicit operator-controlled policy surface.
pub struct CreateOAuthProfileRequest {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub profile_type: String,
    pub is_default: bool,
    pub require_pkce: bool,
    pub require_state_parameter: bool,
    pub require_iss_parameter: bool,
    pub sender_constrained: String,
    pub enforce_refresh_sender_binding: bool,
    pub allowed_grant_types: Vec<String>,
    pub token_endpoint_auth_methods_allowed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateOAuthProfileRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_pkce: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_state_parameter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_iss_parameter: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_constrained: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforce_refresh_sender_binding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_grant_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_allowed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ClientSecret {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub client_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_slot: Option<u32>,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub created_at: String,
    #[cfg_attr(feature = "openapi", schema(format = "date-time"))]
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IssueClientSecretRequest {
    #[cfg_attr(feature = "openapi", schema(format = "uuid"))]
    pub base_configuration_version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct IssueClientSecretResponse {
    pub client_secret_value: String,
    pub client_secret: ClientSecret,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ClientMutationResponse {
    pub client: Client,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OAuthProfileMutationResponse {
    pub oauth_profile: OAuthProfile,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMutationResponse {
    pub connection: Connection,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ClientSecretMutationResponse {
    pub client_secret: ClientSecret,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListClientsResponse {
    pub clients: Vec<Client>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListOAuthProfilesResponse {
    pub oauth_profiles: Vec<OAuthProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListConnectionsResponse {
    pub connections: Vec<Connection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ListClientSecretsResponse {
    pub client_secrets: Vec<ClientSecret>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_info: Option<PageInfo>,
}
