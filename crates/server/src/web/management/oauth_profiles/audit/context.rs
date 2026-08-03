use super::super::super::ManagementEnvironmentRecord;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub(in crate::web::management::oauth_profiles) struct OAuthProfileAuditContext<'a> {
    pub(in crate::web::management::oauth_profiles) environment: &'a ManagementEnvironmentRecord,
    pub(in crate::web::management::oauth_profiles) administrator_id: Uuid,
    pub(in crate::web::management::oauth_profiles) request_id: &'a str,
    pub(in crate::web::management::oauth_profiles) oauth_profile_id: Uuid,
    pub(in crate::web::management::oauth_profiles) configuration_version_id: Uuid,
}

pub(in crate::web::management::oauth_profiles) fn oauth_profile_audit_context<'a>(
    environment: &'a ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &'a str,
    oauth_profile_id: Uuid,
    configuration_version_id: Uuid,
) -> OAuthProfileAuditContext<'a> {
    OAuthProfileAuditContext {
        environment,
        administrator_id,
        request_id,
        oauth_profile_id,
        configuration_version_id,
    }
}
