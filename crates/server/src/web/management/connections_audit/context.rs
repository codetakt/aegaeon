use crate::web::management::ManagementEnvironmentRecord;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub(in crate::web::management) struct ConnectionAuditContext<'a> {
    pub(in crate::web::management::connections_audit) environment: &'a ManagementEnvironmentRecord,
    pub(in crate::web::management::connections_audit) administrator_id: Uuid,
    pub(in crate::web::management::connections_audit) request_id: &'a str,
    pub(in crate::web::management::connections_audit) connection_id: Uuid,
    pub(in crate::web::management::connections_audit) configuration_version_id: Uuid,
}

pub(in crate::web::management) fn connection_audit_context<'a>(
    environment: &'a ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &'a str,
    connection_id: Uuid,
    configuration_version_id: Uuid,
) -> ConnectionAuditContext<'a> {
    ConnectionAuditContext {
        environment,
        administrator_id,
        request_id,
        connection_id,
        configuration_version_id,
    }
}
