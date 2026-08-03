use std::fmt::Write as _;

use crate::management::types::AuditEvent;

/// Convert a list of audit events to CSV format.
pub(super) fn audit_events_to_csv(events: &[AuditEvent]) -> String {
    let mut csv = String::from(
        "id,team_id,tenant_id,environment_id,event_type,category,outcome,severity,occurred_at,actor_type,actor_id,ip_address,target_type,target_id,request_id\n",
    );
    events.iter().for_each(|event| {
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&event.id),
            csv_escape(&event.team_id),
            csv_escape(event.tenant_id.as_deref().unwrap_or("")),
            csv_escape(event.environment_id.as_deref().unwrap_or("")),
            csv_escape(&event.event_type),
            csv_escape(&event.category),
            csv_escape(&event.outcome),
            csv_escape(&event.severity),
            csv_escape(&event.occurred_at),
            csv_escape(&event.actor.actor_type),
            csv_escape(event.actor.actor_id.as_deref().unwrap_or("")),
            csv_escape(event.actor.ip_address.as_deref().unwrap_or("")),
            csv_escape(&event.target.target_type),
            csv_escape(event.target.target_id.as_deref().unwrap_or("")),
            csv_escape(&event.request.request_id),
        );
    });
    csv
}

pub(super) fn csv_escape(s: &str) -> String {
    let formula_sensitive = csv_formula_sensitive(s);
    let cell = if formula_sensitive {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if formula_sensitive
        || cell.contains(',')
        || cell.contains('"')
        || cell.contains('\n')
        || cell.contains('\r')
    {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell
    }
}

fn csv_formula_sensitive(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes
        .first()
        .is_some_and(|first| matches!(first, b'\t' | b'\r' | b'\n'))
    {
        return true;
    }
    bytes
        .iter()
        .copied()
        .find(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .is_some_and(|first_non_space| matches!(first_non_space, b'=' | b'+' | b'-' | b'@'))
}
