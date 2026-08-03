#[macro_use]
mod macros;
mod core_paths;
mod environment_paths;
mod parse;
mod traits;
mod user_paths;

pub(in crate::web::management) use core_paths::{
    TeamApiKeyPath, TeamAuditEventPath, TeamEnvironmentClientPath, TeamEnvironmentClientSecretPath,
    TeamEnvironmentPath, TeamEnvironmentRuntimeKeyPath, TeamPath, TeamTenantPath,
};
pub(in crate::web::management) use environment_paths::{
    TeamEnvironmentAccountLinkPath, TeamEnvironmentConfigurationVersionPath,
    TeamEnvironmentConnectionPath, TeamEnvironmentEntityCachePath, TeamEnvironmentIncidentPath,
    TeamEnvironmentOAuthProfilePath, TeamEnvironmentTrustAnchorPath, TeamEnvironmentTrustChainPath,
    TeamEnvironmentUserPath,
};
pub(in crate::web::management) use parse::{
    parse_optional_uuid_param, parse_team_environment_client_scope,
    parse_team_environment_connection_scope, parse_team_environment_oauth_profile_scope,
    parse_team_environment_scope, parse_team_scope, parse_team_tenant_scope,
};
pub(in crate::web::management) use traits::{
    TeamEnvironmentClientScopedPath, TeamEnvironmentScopedPath, TeamEnvironmentUserScopedPath,
    TeamScopedPath, TeamTenantScopedPath,
};
pub(in crate::web::management) use user_paths::{
    TeamEnvironmentUserGrantPath, TeamEnvironmentUserRefreshTokenPath,
    TeamEnvironmentUserSessionPath, TeamEnvironmentUserTokenPath,
};
