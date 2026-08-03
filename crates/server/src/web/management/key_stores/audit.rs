use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::KeyStorePublicView;

use super::super::{
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
    ManagementEnvironmentRecord,
};
use super::validation::ValidatedKeyStoreUpdate;

pub(in crate::web::management::key_stores) async fn write_key_store_updated_audit(
    tx: &mut Transaction<'_, Postgres>,
    environment: &ManagementEnvironmentRecord,
    administrator_id: Uuid,
    request_id: &str,
    previous: Option<KeyStorePublicView>,
    current: &ValidatedKeyStoreUpdate,
) -> Result<(), Response> {
    let previous = previous.map(|key_store| {
        serde_json::json!({
            "type": key_store.type_,
            "configuration": key_store.configuration,
            "redacted": key_store.redacted,
        })
    });
    let audit_data = serde_json::json!({
        "comment": current.comment.clone(),
        "reason": current.reason.clone(),
        "allowSecurityDowngrade": current.allow_security_downgrade,
        "previous": previous,
        "current": {
            "type": current.type_.clone(),
            "configuration": current.configuration.clone(),
            "redacted": true,
        },
    });
    let target_id = environment.scope.environment.to_string();
    write_management_control_plane_audit_event(
        tx,
        ManagementControlPlaneAuditEvent {
            scope: environment.scope,
            administrator_id,
            request_id,
            event_type: "management.keyStore.updated.v1",
            target_type: "KEY_STORE",
            target_id,
            data: audit_data,
        },
    )
    .await
}
