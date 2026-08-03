mod loading;
mod parsing;
mod roles;

use uuid::Uuid;

pub(super) use loading::{
    ensure_environment_visible, ensure_tenant_visible, load_management_environment_scope,
    require_environment_lifecycle_scope, require_environment_lifecycle_scope_with_issuer_by_ids,
    require_federation_lifecycle_resource_scope, require_federation_lifecycle_scope,
    require_tenant_lifecycle_scope,
};
pub(super) use parsing::{
    parse_optional_uuid_param, parse_team_environment_client_scope,
    parse_team_environment_connection_scope, parse_team_environment_oauth_profile_scope,
    parse_team_environment_scope, parse_team_scope, parse_team_tenant_scope, TeamApiKeyPath,
    TeamAuditEventPath, TeamEnvironmentAccountLinkPath, TeamEnvironmentClientPath,
    TeamEnvironmentClientScopedPath, TeamEnvironmentClientSecretPath,
    TeamEnvironmentConfigurationVersionPath, TeamEnvironmentConnectionPath,
    TeamEnvironmentEntityCachePath, TeamEnvironmentIncidentPath, TeamEnvironmentOAuthProfilePath,
    TeamEnvironmentPath, TeamEnvironmentRuntimeKeyPath, TeamEnvironmentScopedPath,
    TeamEnvironmentTrustAnchorPath, TeamEnvironmentTrustChainPath, TeamEnvironmentUserGrantPath,
    TeamEnvironmentUserPath, TeamEnvironmentUserRefreshTokenPath, TeamEnvironmentUserScopedPath,
    TeamEnvironmentUserSessionPath, TeamEnvironmentUserTokenPath, TeamPath, TeamScopedPath,
    TeamTenantPath,
};
pub(super) use roles::{
    ensure_team_visible, ensure_team_visible_as, require_team_audit_read_access,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
};
#[cfg(test)]
pub(super) use roles::{role_allows_audit_read, role_allows_manage_lifecycle};

#[derive(Clone, Copy, Debug)]
pub(super) struct ManagementEnvironmentScope {
    pub(super) team: Uuid,
    pub(super) tenant: Uuid,
    pub(super) environment: Uuid,
}

#[derive(Clone, Debug)]
pub(super) struct ManagementEnvironmentIssuerScope {
    pub(super) scope: ManagementEnvironmentScope,
    pub(super) issuer_host: String,
}

#[derive(Clone, Debug)]
pub(super) struct ManagementTenantScope {
    pub(super) team: Uuid,
    pub(super) tenant: Uuid,
    pub(super) slug: String,
    pub(super) region: String,
}
