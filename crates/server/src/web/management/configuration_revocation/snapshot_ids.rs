use std::collections::HashSet;
use uuid::Uuid;

pub(in crate::web::management) fn collect_snapshot_ids(
    doc: &serde_json::Value,
    array_key: &str,
    id_fields: &[&str],
    allowed_statuses: Option<&[&str]>,
) -> Vec<Uuid> {
    let mut ids = Vec::new();
    let allowed = allowed_statuses.map(|statuses| {
        statuses
            .iter()
            .map(|s| s.trim().to_ascii_uppercase())
            .collect::<HashSet<String>>()
    });

    let Some(entries) = doc.get(array_key).and_then(|v| v.as_array()) else {
        return ids;
    };

    for entry in entries {
        if let Some(ref allowed_statuses) = allowed {
            if let Some(status) = entry.get("status").and_then(|v| v.as_str()) {
                let status_upper = status.trim().to_ascii_uppercase();
                if !allowed_statuses.contains(&status_upper) {
                    continue;
                }
            }
        }

        for key in id_fields {
            if let Some(id_str) = entry.get(*key).and_then(|v| v.as_str()) {
                if let Ok(id) = Uuid::parse_str(id_str.trim()) {
                    ids.push(id);
                    break;
                }
            }
        }
    }

    ids.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ids.dedup_by(|a, b| a.as_bytes() == b.as_bytes());
    ids
}
