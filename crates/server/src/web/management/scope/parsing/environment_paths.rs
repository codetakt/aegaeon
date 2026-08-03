use super::super::super::parse_uuid_param;
use super::parse::parse_team_scope;
use super::traits::{
    TeamEnvironmentConnectionScopedPath, TeamEnvironmentOAuthProfileScopedPath,
    TeamEnvironmentScopedPath, TeamEnvironmentUserScopedPath, TeamScopedPath,
};
use axum::response::Response;
use serde::Deserialize;
use uuid::Uuid;

team_environment_resource_path_struct!(
    TeamEnvironmentConnectionPath,
    connection_id,
    "connectionId"
);
impl TeamEnvironmentConnectionScopedPath for TeamEnvironmentConnectionPath {
    fn connection_id_raw(&self) -> &str {
        &self.connection_id
    }
}

team_environment_resource_path_struct!(
    TeamEnvironmentOAuthProfilePath,
    oauth_profile_id,
    "oauthProfileId"
);
impl TeamEnvironmentOAuthProfileScopedPath for TeamEnvironmentOAuthProfilePath {
    fn oauth_profile_id_raw(&self) -> &str {
        &self.oauth_profile_id
    }
}

team_environment_resource_path_struct!(
    TeamEnvironmentAccountLinkPath,
    account_link_id,
    "accountLinkId"
);

team_environment_resource_path_struct!(
    TeamEnvironmentConfigurationVersionPath,
    configuration_version_id,
    "configurationVersionId"
);

team_environment_resource_path_struct!(
    TeamEnvironmentEntityCachePath,
    entity_cache_id,
    "entityCacheId"
);

team_environment_resource_path_struct!(TeamEnvironmentIncidentPath, incident_id, "incidentId");

team_environment_resource_path_struct!(
    TeamEnvironmentTrustAnchorPath,
    trust_anchor_id,
    "trustAnchorId"
);

team_environment_resource_path_struct!(
    TeamEnvironmentTrustChainPath,
    trust_chain_id,
    "trustChainId"
);

team_environment_resource_path_struct!(TeamEnvironmentUserPath, user_id, "userId");

impl TeamEnvironmentAccountLinkPath {
    pub(in crate::web::management) fn account_link_id(
        &self,
        request_id: &str,
    ) -> Result<Uuid, Response> {
        parse_uuid_param(&self.account_link_id, "accountLinkId", request_id)
    }
}

impl TeamEnvironmentConfigurationVersionPath {
    pub(in crate::web::management) fn configuration_version_id(
        &self,
        request_id: &str,
    ) -> Result<Uuid, Response> {
        parse_uuid_param(
            &self.configuration_version_id,
            "configurationVersionId",
            request_id,
        )
    }
}

impl TeamEnvironmentEntityCachePath {
    pub(in crate::web::management) fn entity_cache_id(
        &self,
        request_id: &str,
    ) -> Result<Uuid, Response> {
        parse_uuid_param(&self.entity_cache_id, "entityCacheId", request_id)
    }
}

impl TeamEnvironmentIncidentPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid, Uuid), Response> {
        Ok((
            parse_team_scope(self, request_id)?,
            parse_uuid_param(&self.environment_id, "environmentId", request_id)?,
            parse_uuid_param(&self.incident_id, "incidentId", request_id)?,
        ))
    }
}

impl TeamEnvironmentTrustAnchorPath {
    pub(in crate::web::management) fn trust_anchor_id(
        &self,
        request_id: &str,
    ) -> Result<Uuid, Response> {
        parse_uuid_param(&self.trust_anchor_id, "trustAnchorId", request_id)
    }
}

impl TeamEnvironmentTrustChainPath {
    pub(in crate::web::management) fn trust_chain_id(
        &self,
        request_id: &str,
    ) -> Result<Uuid, Response> {
        parse_uuid_param(&self.trust_chain_id, "trustChainId", request_id)
    }
}

impl TeamEnvironmentUserScopedPath for TeamEnvironmentUserPath {
    fn user_id_raw(&self) -> &str {
        &self.user_id
    }
}
