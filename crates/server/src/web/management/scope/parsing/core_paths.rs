use super::super::super::parse_uuid_param;
use super::parse::{
    parse_team_environment_client_scope, parse_team_environment_scope, parse_team_scope,
};
use super::traits::{
    TeamEnvironmentClientScopedPath, TeamEnvironmentScopedPath, TeamScopedPath,
    TeamTenantScopedPath,
};
use axum::response::Response;
use serde::Deserialize;
use uuid::Uuid;

team_path_struct!(TeamPath);

impl TeamPath {
    pub(in crate::web::management) fn id(&self, request_id: &str) -> Result<Uuid, Response> {
        parse_team_scope(self, request_id)
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamApiKeyPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "apiKeyId")]
    api_key_id: String,
}

impl_team_path!(TeamApiKeyPath);

impl TeamApiKeyPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid), Response> {
        Ok((
            parse_team_scope(self, request_id)?,
            parse_uuid_param(&self.api_key_id, "apiKeyId", request_id)?,
        ))
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamAuditEventPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "auditEventId")]
    audit_event_id: String,
}

impl_team_path!(TeamAuditEventPath);

impl TeamAuditEventPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid), Response> {
        Ok((
            parse_team_scope(self, request_id)?,
            parse_uuid_param(&self.audit_event_id, "auditEventId", request_id)?,
        ))
    }
}

team_tenant_path_struct!(TeamTenantPath);

team_environment_path_struct!(TeamEnvironmentPath);

impl TeamEnvironmentPath {
    #[cfg(test)]
    pub(in crate::web::management) fn for_tests(team_id: Uuid, environment_id: Uuid) -> Self {
        Self {
            team_id: team_id.to_string(),
            environment_id: environment_id.to_string(),
        }
    }

    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid), Response> {
        parse_team_environment_scope(self, request_id)
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamEnvironmentClientPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "environmentId")]
    environment_id: String,
    #[serde(rename = "clientId")]
    client_id: String,
}

impl_team_environment_client_path!(TeamEnvironmentClientPath);

impl TeamEnvironmentClientPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid, Uuid), Response> {
        parse_team_environment_client_scope(self, request_id)
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamEnvironmentClientSecretPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "environmentId")]
    environment_id: String,
    #[serde(rename = "clientId")]
    client_id: String,
    #[serde(rename = "clientSecretId")]
    client_secret_id: String,
}

impl_team_environment_client_path!(TeamEnvironmentClientSecretPath);

impl TeamEnvironmentClientSecretPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid, Uuid, Uuid), Response> {
        let (team_id, environment_id, client_id) =
            parse_team_environment_client_scope(self, request_id)?;
        Ok((
            team_id,
            environment_id,
            client_id,
            parse_uuid_param(&self.client_secret_id, "clientSecretId", request_id)?,
        ))
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamEnvironmentRuntimeKeyPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "environmentId")]
    environment_id: String,
    #[serde(rename = "runtimeKeyId")]
    runtime_key_id: String,
}

impl_team_environment_path!(TeamEnvironmentRuntimeKeyPath);

impl TeamEnvironmentRuntimeKeyPath {
    #[cfg(test)]
    pub(in crate::web::management) fn for_tests(
        team_id: Uuid,
        environment_id: Uuid,
        runtime_key_id: Uuid,
    ) -> Self {
        Self {
            team_id: team_id.to_string(),
            environment_id: environment_id.to_string(),
            runtime_key_id: runtime_key_id.to_string(),
        }
    }

    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid, Uuid), Response> {
        Ok((
            parse_team_scope(self, request_id)?,
            parse_uuid_param(&self.environment_id, "environmentId", request_id)?,
            parse_uuid_param(&self.runtime_key_id, "runtimeKeyId", request_id)?,
        ))
    }
}
