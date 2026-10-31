//! Independent compiled-source checks for normal CLI and server construction.
//! SQL's installer premise does not replace these whole-file identities.
use super::digest::metadata_text;
use super::{frame, sha256_hex, HistoryInputError};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261029050000_subject_ownership.sql");
const FORWARD_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261029052000_subject_prerequisite_catalog.sql");
const ORGANIZATION_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261031110000_identity_creation_catalog.sql");
const CREATION_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261031100000_identity_creation_receipts.sql");
const IDENTITY_MIGRATION: &str = include_str!(
    "../../../../../db/migrations/20261030190000_organization_identity_generation.sql"
);
const ENROLLMENT_MIGRATION: &str = include_str!(
    "../../../../../db/migrations/20261030210000_organization_identity_enrollment.sql"
);
const SUPPORT_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261030230000_organization_support_policy.sql");
const ADMIN_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261030250000_organization_admin_access.sql");
const SNAPSHOT_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261030270000_organization_snapshot_history.sql");
const IMPORT_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261031010000_organization_import_target.sql");
const DEPENDENCY_MIGRATION: &str = include_str!(
    "../../../../../db/migrations/20261031030000_organization_snapshot_dependencies.sql"
);
const REGISTRATION_MIGRATION: &str = include_str!(
    "../../../../../db/migrations/20261031050000_organization_registration_dependencies.sql"
);
const INACTIVE_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261031070000_organization_inactive_import.sql");
const ATLAS_SUM: &str = include_str!("../../../../../db/migrations/atlas.sum");
// PostgreSQL's to_jsonb(pg_catalog row) represents the OID type as a
// decimal JSON string, unlike integer-typed catalog fields.
fn catalog_oid(value: &Value) -> Option<u32> {
    value.as_str()?.parse().ok()
}

fn refuse(reason: &'static str) -> HistoryInputError {
    HistoryInputError(reason.into())
}

fn compiled_definitions() -> Result<HashMap<&'static str, &'static str>, HistoryInputError> {
    let mut definitions = HashMap::new();
    for (source, marker) in [
        (MIGRATION, "CREATE FUNCTION aegaeon."),
        (IDENTITY_MIGRATION, "CREATE FUNCTION aegaeon."),
        (ENROLLMENT_MIGRATION, "CREATE FUNCTION aegaeon."),
        (SUPPORT_MIGRATION, "CREATE FUNCTION aegaeon."),
        (ADMIN_MIGRATION, "CREATE FUNCTION aegaeon."),
        (SNAPSHOT_MIGRATION, "CREATE FUNCTION aegaeon."),
        (IMPORT_MIGRATION, "CREATE FUNCTION aegaeon."),
        (INACTIVE_MIGRATION, "CREATE FUNCTION aegaeon."),
        (CREATION_MIGRATION, "CREATE FUNCTION aegaeon."),
        (ENROLLMENT_MIGRATION, "CREATE OR REPLACE FUNCTION aegaeon."),
        (DEPENDENCY_MIGRATION, "CREATE OR REPLACE FUNCTION aegaeon."),
        (
            REGISTRATION_MIGRATION,
            "CREATE OR REPLACE FUNCTION aegaeon.",
        ),
        (FORWARD_MIGRATION, "CREATE OR REPLACE FUNCTION aegaeon."),
        (
            ORGANIZATION_MIGRATION,
            "CREATE OR REPLACE FUNCTION aegaeon.",
        ),
    ] {
        for definition in source.split(marker).skip(1) {
            let name = definition
                .split_once('(')
                .ok_or_else(|| refuse("invalid compiled function definition"))?
                .0;
            definitions.insert(name, definition);
        }
    }
    Ok(definitions)
}

pub(crate) fn catalog_row_bound() -> Result<usize, HistoryInputError> {
    Ok(compiled_definitions()?.len()
        + ATLAS_SUM
            .lines()
            .skip(1)
            .filter(|line| !line.is_empty())
            .count()
        + 1)
}

/// Finite envelope for the independent function/revision/owner-role subset.
/// A catalog row contains both prosrc and pg_get_functiondef, with JSON escaping.
/// Application snapshot row limits do not apply to embedded SQL definitions.
pub(crate) fn catalog_payload_bound() -> Result<usize, HistoryInputError> {
    let metadata = catalog_row_bound()?
        .checked_mul(65536)
        .ok_or_else(|| refuse("catalog bound overflow"))?;
    compiled_definitions()?
        .values()
        .try_fold(metadata, |total, definition| {
            let length = definition
                .split_once("$function$;")
                .ok_or_else(|| refuse("compiled function terminator"))?
                .0
                .len();
            length
                .checked_mul(12)
                .and_then(|bytes| total.checked_add(bytes))
                .ok_or_else(|| refuse("catalog bound overflow"))
        })
}

pub(crate) fn verify_compiled_catalog(
    rows: &[(String, Value)],
    schema_sha256: &str,
    runtime_role: &str,
) -> Result<(), HistoryInputError> {
    let roles: HashMap<_, _> = rows
        .iter()
        .filter(|(key, _)| key.starts_with("role:"))
        .filter_map(|(_, r)| Some((catalog_oid(&r["oid"])?, r["rolname"].as_str()?)))
        .collect();
    let mut functions = HashMap::new();
    for (_, row) in rows.iter().filter(|(key, _)| key.starts_with("function:")) {
        let name = row["proname"]
            .as_str()
            .ok_or_else(|| refuse("invalid function catalog"))?;
        if functions.insert(name, row).is_some() {
            return Err(refuse("unexpected protected function overload"));
        }
    }
    for definition in compiled_definitions()?.into_values() {
        let (name, remainder) = definition
            .split_once('(')
            .ok_or_else(|| refuse("invalid compiled function definition"))?;
        let (header, body) = remainder
            .split_once("AS $function$")
            .ok_or_else(|| refuse("invalid compiled function definition"))?;
        let body = body
            .split_once("$function$;")
            .ok_or_else(|| refuse("invalid compiled function body"))?
            .0;
        let observed = functions
            .remove(name)
            .ok_or_else(|| refuse("protected function missing from catalog"))?;
        let owner = catalog_oid(&observed["proowner"])
            .and_then(|oid| roles.get(&oid))
            .copied();
        if observed["prosrc"].as_str() != Some(body)
            || owner != Some("aegaeon_subject_owner")
            || observed["prosecdef"].as_bool() != Some(header.contains("SECURITY DEFINER"))
        {
            return Err(refuse("protected function differs from compiled source"));
        }
        if name == "validate_subject_ownership_namespace_v1" {
            let acl = observed["acl"]
                .as_array()
                .ok_or_else(|| refuse("runtime entry ACL missing"))?;
            if !acl.iter().any(|a| {
                a["grantee"] == runtime_role
                    && a["privilege"] == "EXECUTE"
                    && a["grantable"] == false
            }) || acl.iter().any(|a| {
                a["privilege"] != "EXECUTE"
                    || a["grantee"] != "aegaeon_subject_owner"
                        && (a["grantee"] != runtime_role || a["grantable"] != false)
            }) || observed["proconfig"] != serde_json::json!(["search_path=pg_catalog, pg_temp"])
                || observed["provolatile"] != "s"
                || observed["proisstrict"] != false
                || observed["proretset"] != true
                || observed["pronargs"] != 1
                || observed["pronargdefaults"] != 0
                || observed["prokind"] != "f"
            {
                return Err(refuse(
                    "runtime entry settings or ACL differ from compiled authority",
                ));
            }
        }
        // The SQL checker validates all other helpers' complete settings. Its own
        // settings must independently match here as well as its exact full body.
        if name == "subject_history_preflight"
            && (observed["proconfig"] != serde_json::json!(["search_path=pg_catalog, pg_temp"])
                || observed["provolatile"].as_str() != Some("s")
                || observed["proisstrict"].as_bool() != Some(false)
                || observed["proretset"].as_bool() != Some(false)
                || catalog_oid(&observed["prorettype"]) != Some(25)
                || observed["pronargs"].as_u64() != Some(1)
                || observed["pronargdefaults"].as_u64() != Some(0)
                || observed["prokind"].as_str() != Some("f")
                || !observed["definition"]
                    .as_str()
                    .is_some_and(|d| d.contains("LANGUAGE plpgsql")))
        {
            return Err(refuse(
                "physical checker settings differ from compiled source",
            ));
        }
    }
    if !functions.is_empty() {
        return Err(refuse("unexpected protected function"));
    }
    let revisions: Vec<_> = rows
        .iter()
        .filter(|(key, _)| key.starts_with("atlas_revision:"))
        .map(|(_, row)| row)
        .collect();
    verify_revisions(&revisions, ATLAS_SUM)?;
    if physical_contract_hash()? != schema_sha256 {
        return Err(refuse(
            "physical contract identity differs from compiled source",
        ));
    }
    Ok(())
}

fn verify_revisions(rows: &[&Value], inventory: &str) -> Result<(), HistoryInputError> {
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
            || row["hash"]
                .as_str()
                .map(|h| h.strip_prefix("h1:").unwrap_or(h))
                != Some(*hash)
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

pub(super) fn physical_contract_hash() -> Result<String, HistoryInputError> {
    fn literal(marker: &str, terminator: &str) -> Result<Value, HistoryInputError> {
        let text = ORGANIZATION_MIGRATION
            .split_once(marker)
            .and_then(|(_, rest)| rest.split_once(terminator))
            .map(|(value, _)| value)
            .ok_or_else(|| refuse("missing compiled physical contract"))?;
        serde_json::from_str(text).map_err(|_| refuse("invalid compiled physical contract"))
    }
    let physical = literal("expected jsonb := $physical$", "$physical$::jsonb;")?;
    let functions = literal(
        "expected_functions jsonb := $functions$",
        "$functions$::jsonb;",
    )?;
    let revisions = literal(
        "expected_revisions jsonb := $revisions$",
        "$revisions$::jsonb;",
    )?;
    let mut bytes = frame(b"aegaeon-subject-physical-v1");
    for value in [physical, functions, revisions] {
        bytes.extend(frame(metadata_text(&value).as_bytes()));
    }
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_compiled_revision_including_final_hash_is_required() {
        let manifest = "h1:aggregate\n1_first.sql h1:AAAA\n2_final.sql h1:BBBB\n";
        let first = serde_json::json!({"version":"1","description":"first","hash":"AAAA","applied":1,"total":1,"error":null});
        let mut last = serde_json::json!({"version":"2","description":"final","hash":"BBBB","applied":1,"total":1,"error":null});
        assert!(verify_revisions(&[&first, &last], manifest).is_ok());
        assert!(verify_revisions(&[&last], manifest).is_err());
        assert!(verify_revisions(&[&first, &first, &last], manifest).is_err());
        last["hash"] = serde_json::json!("different");
        assert!(verify_revisions(&[&first, &last], manifest).is_err());
        last["hash"] = serde_json::json!("BBBB");
        last["applied"] = serde_json::json!(0);
        assert!(verify_revisions(&[&first, &last], manifest).is_err());
    }
    #[test]
    fn physical_contract_is_embedded_independently_of_checker() {
        assert_eq!(physical_contract_hash().unwrap().len(), 64);
    }
}
