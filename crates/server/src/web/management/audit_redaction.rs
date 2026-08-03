pub(super) use crate::audit_safety::redact_json_value;
pub(crate) use crate::audit_safety::redacted_audit_data;
use crate::management::types::AuditEvent;

/// Redact sensitive patterns from audit event `json_patch` and data fields.
/// Removes credential, one-time token, private-key, and encrypted value fields.
pub(super) fn redact_audit_event(event: &mut AuditEvent) {
    if let Some(ref mut patch) = event.change {
        if let Some(ref mut jp) = patch.json_patch {
            redact_json_value(jp);
        }
    }
    if let Some(ref mut data) = event.data {
        redact_json_value(data);
    }
}
