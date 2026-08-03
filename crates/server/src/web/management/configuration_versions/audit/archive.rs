use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::super::super::configuration_documents::ConfigurationVersionAuditContext;
use super::writer::write_configuration_version_transition_audit_event;

pub(in crate::web::management::configuration_versions) async fn write_configuration_archive_audit(
    tx: &mut Transaction<'_, Postgres>,
    context: &ConfigurationVersionAuditContext<'_>,
    archived_configuration_version_id: Uuid,
) -> Result<(), Response> {
    write_configuration_version_transition_audit_event(
        tx,
        context,
        "CONFIGURATION_VERSION_ARCHIVED",
        "INFO",
        serde_json::json!({
            "archivedConfigurationVersionId": archived_configuration_version_id.to_string(),
        }),
    )
    .await
}
