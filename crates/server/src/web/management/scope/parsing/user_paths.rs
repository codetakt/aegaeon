use super::super::super::parse_uuid_param;
use super::parse::{parse_team_scope, require_non_empty_path_value};
use super::traits::{TeamEnvironmentScopedPath, TeamEnvironmentUserScopedPath, TeamScopedPath};
use axum::response::Response;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamEnvironmentUserSessionPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "environmentId")]
    environment_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "sessionId")]
    session_id: String,
}

impl_team_environment_path!(TeamEnvironmentUserSessionPath);

impl TeamEnvironmentUserScopedPath for TeamEnvironmentUserSessionPath {
    fn user_id_raw(&self) -> &str {
        &self.user_id
    }
}

impl TeamEnvironmentUserSessionPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid, Uuid, String), Response> {
        Ok((
            parse_team_scope(self, request_id)?,
            parse_uuid_param(&self.environment_id, "environmentId", request_id)?,
            parse_uuid_param(&self.user_id, "userId", request_id)?,
            require_non_empty_path_value(&self.session_id, "sessionId", request_id)?,
        ))
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamEnvironmentUserGrantPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "environmentId")]
    environment_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "grantId")]
    grant_id: String,
}

impl_team_environment_path!(TeamEnvironmentUserGrantPath);

impl TeamEnvironmentUserScopedPath for TeamEnvironmentUserGrantPath {
    fn user_id_raw(&self) -> &str {
        &self.user_id
    }
}

impl TeamEnvironmentUserGrantPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid, Uuid, String), Response> {
        Ok((
            parse_team_scope(self, request_id)?,
            parse_uuid_param(&self.environment_id, "environmentId", request_id)?,
            parse_uuid_param(&self.user_id, "userId", request_id)?,
            require_non_empty_path_value(&self.grant_id, "grantId", request_id)?,
        ))
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamEnvironmentUserRefreshTokenPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "environmentId")]
    environment_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "refreshTokenId")]
    refresh_token_id: String,
}

impl_team_environment_path!(TeamEnvironmentUserRefreshTokenPath);

impl TeamEnvironmentUserScopedPath for TeamEnvironmentUserRefreshTokenPath {
    fn user_id_raw(&self) -> &str {
        &self.user_id
    }
}

impl TeamEnvironmentUserRefreshTokenPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid, Uuid, String), Response> {
        Ok((
            parse_team_scope(self, request_id)?,
            parse_uuid_param(&self.environment_id, "environmentId", request_id)?,
            parse_uuid_param(&self.user_id, "userId", request_id)?,
            require_non_empty_path_value(&self.refresh_token_id, "refreshTokenId", request_id)?,
        ))
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::web::management) struct TeamEnvironmentUserTokenPath {
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "environmentId")]
    environment_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "tokenId")]
    token_id: String,
}

impl_team_environment_path!(TeamEnvironmentUserTokenPath);

impl TeamEnvironmentUserScopedPath for TeamEnvironmentUserTokenPath {
    fn user_id_raw(&self) -> &str {
        &self.user_id
    }
}

impl TeamEnvironmentUserTokenPath {
    pub(in crate::web::management) fn ids(
        &self,
        request_id: &str,
    ) -> Result<(Uuid, Uuid, Uuid, Uuid), Response> {
        Ok((
            parse_team_scope(self, request_id)?,
            parse_uuid_param(&self.environment_id, "environmentId", request_id)?,
            parse_uuid_param(&self.user_id, "userId", request_id)?,
            parse_uuid_param(&self.token_id, "tokenId", request_id)?,
        ))
    }
}
