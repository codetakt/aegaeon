use super::super::ManagementEnvironmentRecord;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub(in crate::web::management) struct ClientAuditContext<'a> {
    pub(in crate::web::management::client_audit) environment: &'a ManagementEnvironmentRecord,
    pub(in crate::web::management::client_audit) administrator_id: Uuid,
    pub(in crate::web::management::client_audit) request_id: &'a str,
    pub(in crate::web::management::client_audit) client_id: Uuid,
    pub(in crate::web::management::client_audit) configuration_version_id: Uuid,
}

pub(in crate::web::management) fn client_audit_context<'a>(
    environment: &'a ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &'a str,
    client_id: Uuid,
    configuration_version_id: Uuid,
) -> ClientAuditContext<'a> {
    ClientAuditContext {
        environment,
        administrator_id,
        request_id,
        client_id,
        configuration_version_id,
    }
}
