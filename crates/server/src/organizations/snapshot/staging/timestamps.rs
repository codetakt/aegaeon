//! Compare typed database instants without rewriting retained source bytes.
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(super) fn valid(value: &str) -> bool {
    parse(value).is_some()
}
fn parse(value: &str) -> Option<OffsetDateTime> {
    // The RFC3339 parser may discard fractional digits beyond nanoseconds.
    // Check the retained lexeme before allowing a microsecond-only database.
    if value.split_once('.').is_some_and(|(_, fraction)| {
        fraction
            .bytes()
            .take_while(u8::is_ascii_digit)
            .skip(6)
            .any(|b| b != b'0')
    }) {
        return None;
    }
    let value = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    (value.nanosecond() % 1000 == 0).then_some(value)
}
fn timestamp(section: &str, field: &str) -> bool {
    match section {
        "identities" => matches!(field, "created_at" | "updated_at"),
        "namespace" | "owners" | "subject_history" => field == "recorded_at",
        "client_bindings" | "operators" | "organizations" | "audit" | "receipts" => {
            field == "created_at"
        }
        _ => false,
    }
}
pub(super) fn equivalent(section: &str, source: &Value, target: &Value) -> bool {
    let (Some(source), Some(target)) = (source.as_object(), target.as_object()) else {
        return false;
    };
    source.len() == target.len()
        && source.iter().all(|(key, source)| {
            let Some(target) = target.get(key) else {
                return false;
            };
            if timestamp(section, key) {
                let source = source.as_str().and_then(parse);
                let target = target.as_str().and_then(parse);
                source.is_some() && source == target
            } else {
                source == target
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn snapshot_timestamps_preserve_non_timestamp_strings_and_nested_payloads() {
        let source = json!({"created_at":"2026-10-31T09:00:00+09:00","external_id":"É","data":{"created_at":"2026-10-31T09:00:00+09:00"}});
        let mut target = source.clone();
        target["created_at"] = json!("2026-10-31T00:00:00Z");
        assert!(equivalent("organizations", &source, &target));
        for (field, value) in [
            ("external_id", json!("é")),
            ("external_id", json!("E\u{301}")),
            ("data", json!({"created_at":"2026-10-31T00:00:00Z"})),
            ("created_at", json!("2026-10-31T00:00:00.000001Z")),
        ] {
            let mut different = target.clone();
            different[field] = value;
            assert!(!equivalent("organizations", &source, &different));
        }
        assert!(!valid("2026-10-31T00:00:00.000000001Z"));
        assert!(valid("2026-10-31T00:00:00.000001000Z"));
        assert!(!valid("2026-10-31T00:00:00.0000010001Z"));
        assert!(valid("2026-10-31T00:00:00.000001000000Z"));
    }
}
