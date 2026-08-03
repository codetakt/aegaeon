pub(in crate::web::management) trait TeamScopedPath {
    fn team_id_raw(&self) -> &str;
}

pub(in crate::web::management) trait TeamTenantScopedPath:
    TeamScopedPath
{
    fn tenant_id_raw(&self) -> &str;
}

pub(in crate::web::management) trait TeamEnvironmentScopedPath:
    TeamScopedPath
{
    fn environment_id_raw(&self) -> &str;
}

pub(in crate::web::management) trait TeamEnvironmentClientScopedPath:
    TeamEnvironmentScopedPath
{
    fn client_id_raw(&self) -> &str;
}

pub(in crate::web::management) trait TeamEnvironmentOAuthProfileScopedPath:
    TeamEnvironmentScopedPath
{
    fn oauth_profile_id_raw(&self) -> &str;
}

pub(in crate::web::management) trait TeamEnvironmentConnectionScopedPath:
    TeamEnvironmentScopedPath
{
    fn connection_id_raw(&self) -> &str;
}

pub(in crate::web::management) trait TeamEnvironmentUserScopedPath:
    TeamEnvironmentScopedPath
{
    fn user_id_raw(&self) -> &str;
}
