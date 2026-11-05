use super::*;

#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateOrganizationRequest {
    pub external_id: String,
    pub reason: String,
}

#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationResponse {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub environment_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub domain_id: Uuid,
    pub external_id: String,
    pub state: crate::organizations::OrganizationState,
    pub revision: i64,
}

impl From<crate::organizations::Organization> for OrganizationResponse {
    fn from(value: crate::organizations::Organization) -> Self {
        Self {
            id: value.id,
            environment_id: value.scope.environment_id,
            domain_id: value.scope.domain_id,
            external_id: value.external_id,
            state: value.state,
            revision: value.revision,
        }
    }
}

#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationListResponse {
    pub organizations: Vec<OrganizationResponse>,
    pub page_info: crate::management::types::PageInfo,
}
