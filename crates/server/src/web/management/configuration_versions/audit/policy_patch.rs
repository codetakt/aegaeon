use axum::response::Response;
use sqlx::{Postgres, Transaction};

use super::super::super::configuration_documents::ConfigurationVersionAuditContext;
use super::writer::write_configuration_version_transition_audit_event;
use crate::management::types::PolicyPatchRequest;

pub(in crate::web::management::configuration_versions) async fn write_policy_patch_audit(
    tx: &mut Transaction<'_, Postgres>,
    context: &ConfigurationVersionAuditContext<'_>,
    request: &PolicyPatchRequest,
    downgraded_fields: &[&'static str],
) -> Result<(), Response> {
    let severity = if downgraded_fields.is_empty() {
        "INFO"
    } else {
        "WARN"
    };
    let data = serde_json::json!({
        "reason": request.reason,
        "comment": request.comment,
        "securityDowngrade": (!downgraded_fields.is_empty()).then_some(downgraded_fields),
    });
    write_configuration_version_transition_audit_event(
        tx,
        context,
        "POLICIES_PATCHED",
        severity,
        data,
    )
    .await
}
