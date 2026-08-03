use uuid::Uuid;

use super::super::ManagementEnvironmentScope;

#[derive(Clone, Debug)]
pub(in crate::web::management) struct ManagementEnvironmentRecord {
    pub(in crate::web::management) scope: ManagementEnvironmentScope,
    pub(in crate::web::management) name: String,
    pub(in crate::web::management) slug: String,
    pub(in crate::web::management) issuer_host: String,
    pub(in crate::web::management) issuer_url: String,
    pub(in crate::web::management) active_configuration_version_id: Uuid,
    pub(in crate::web::management) created_at: String,
    pub(in crate::web::management) updated_at: String,
}

pub(in crate::web::management) type EnvironmentRow = (
    Uuid,
    String,
    String,
    String,
    String,
    Option<Uuid>,
    String,
    String,
);
