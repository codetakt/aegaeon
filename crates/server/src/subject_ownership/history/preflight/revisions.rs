//! Exact accepted historical Atlas prefix, never a wildcard or ledger rewrite.
use super::{refuse, sha256_hex, HistoryInputError, Value, ATTRIBUTE_MIGRATION};
use std::collections::{HashMap, HashSet};

fn published_prefixes() -> Result<HashMap<String, String>, HistoryInputError> {
    let sources = [
        (
            "20261101090000_user_attribute_sources.sql",
            ATTRIBUTE_MIGRATION,
        ),
        (
            "20261102100000_lti_platform.sql",
            include_str!("../../../../../../db/migrations/20261102100000_lti_platform.sql"),
        ),
        (
            "20261102101000_lti_subject_inventory.sql",
            include_str!(
                "../../../../../../db/migrations/20261102101000_lti_subject_inventory.sql"
            ),
        ),
        (
            "20261102102000_lti_admission_index.sql",
            include_str!("../../../../../../db/migrations/20261102102000_lti_admission_index.sql"),
        ),
        (
            "20261102103000_lti_admission_inventory.sql",
            super::LTI_MIGRATION,
        ),
    ];
    let registry: Value = serde_json::from_str(include_str!(
        "../../../../../../spec/subject-ownership/atlas-prefix-hashes.v1.json"
    ))
    .map_err(|_| refuse("invalid compiled Atlas prefix inventory"))?;
    let entries = registry["entries"]
        .as_array()
        .ok_or_else(|| refuse("invalid compiled Atlas prefix entries"))?;
    if registry["schema_version"] != 1 || entries.len() != sources.len() {
        return Err(refuse("published Atlas prefix inventory differs"));
    }
    let mut result = HashMap::new();
    for entry in entries {
        let (filename, source) = sources
            .iter()
            .find(|(filename, _)| entry["migration"] == *filename)
            .ok_or_else(|| refuse("unknown published Atlas prefix source"))?;
        if entry["source_sha256"].as_str() != Some(&sha256_hex(source.as_bytes())) {
            return Err(refuse("published Atlas prefix source differs"));
        }
        let prefix = entry["prefix_hash"]
            .as_str()
            .ok_or_else(|| refuse("missing published Atlas prefix hash"))?;
        let version = filename
            .split_once('_')
            .ok_or_else(|| refuse("invalid published revision"))?
            .0;
        if prefix.len() != 44
            || !prefix.ends_with('=')
            || !prefix[..43]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
            || result
                .insert(version.to_owned(), prefix.to_owned())
                .is_some()
        {
            return Err(refuse("invalid or duplicate published prefix"));
        }
    }
    Ok(result)
}

pub(super) fn verify_revisions(rows: &[&Value], inventory: &str) -> Result<(), HistoryInputError> {
    let mut expected = HashMap::new();
    for line in inventory.lines().skip(1).filter(|line| !line.is_empty()) {
        let mut fields = line.split_whitespace();
        let filename = fields
            .next()
            .ok_or_else(|| refuse("invalid compiled Atlas inventory"))?;
        let hash = fields
            .next()
            .and_then(|s| s.strip_prefix("h1:"))
            .ok_or_else(|| refuse("invalid compiled Atlas hash"))?;
        let stem = filename
            .strip_suffix(".sql")
            .ok_or_else(|| refuse("invalid compiled migration name"))?;
        let (version, description) = stem
            .split_once('_')
            .ok_or_else(|| refuse("invalid compiled migration name"))?;
        if fields.next().is_some()
            || expected
                .insert(version, (description, hash, stem))
                .is_some()
        {
            return Err(refuse("invalid compiled Atlas inventory"));
        }
    }
    let published = published_prefixes()?;
    let mut seen = HashSet::new();
    for row in rows {
        let version = row["version"]
            .as_str()
            .ok_or_else(|| refuse("missing Atlas revision"))?;
        let (key, (description, hash, _)) = expected
            .iter()
            .find(|(key, (_, _, stem))| version == **key || version == *stem)
            .ok_or_else(|| refuse("unexpected Atlas revision"))?;
        if !seen.insert(*key)
            || row["description"].as_str() != Some(*description)
            || !row["hash"].as_str().is_some_and(|value| {
                let value = value.strip_prefix("h1:").unwrap_or(value);
                value == *hash || published.get(*key).is_some_and(|prefix| value == prefix)
            })
            || row["applied"].as_u64().is_none()
            || row["applied"].as_u64() != row["total"].as_u64()
            || row["total"].as_u64() == Some(0)
            || !matches!(row.get("error"), Some(Value::Null)) && row["error"].as_str() != Some("")
        {
            return Err(refuse("incomplete or mismatched compiled Atlas revision"));
        }
    }
    if seen.len() != expected.len() {
        return Err(refuse("missing compiled Atlas revision"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_prefix_requires_the_exact_revision_and_complete_current_inventory() {
        let prefix = published_prefixes().unwrap()["20261101090000"].clone();
        let inventory = "h1:aggregate\n20261101090000_user_attribute_sources.sql h1:CURRENT\n20261102000000_organization_attribute_catalog.sql h1:FINAL\n";
        let attribute = serde_json::json!({"version":"20261101090000",
            "description":"user_attribute_sources","hash":prefix,"applied":1,"total":1,"error":null});
        let mut final_row = serde_json::json!({"version":"20261102000000",
            "description":"organization_attribute_catalog","hash":"FINAL","applied":1,"total":1,"error":null});
        assert!(verify_revisions(&[&attribute, &final_row], inventory).is_ok());
        assert!(verify_revisions(&[&attribute], inventory).is_err());
        final_row["hash"] = attribute["hash"].clone();
        assert!(verify_revisions(&[&attribute, &final_row], inventory).is_err());
        final_row["hash"] = serde_json::json!("FINAL");
        let mut changed = attribute.clone();
        for value in [
            Value::Null,
            serde_json::json!("unknown"),
            serde_json::json!("h1:"),
        ] {
            changed["hash"] = value;
            assert!(verify_revisions(&[&changed, &final_row], inventory).is_err());
        }
    }
}
