//! Independent compiled-source checks for normal CLI and server construction.
//! SQL's installer premise does not replace these whole-file identities.
use super::digest::metadata_text;
use super::{frame, sha256_hex, HistoryInputError};
use serde_json::Value;
use std::collections::HashMap;

mod revisions;
use revisions::verify_revisions;

const MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261029050000_subject_ownership.sql");
const FORWARD_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261029052000_subject_prerequisite_catalog.sql");
const ATTRIBUTE_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261101090000_user_attribute_sources.sql");
const LTI_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261102103000_lti_admission_inventory.sql");
const MANAGEMENT_MIGRATION: &str =
    include_str!("../../../../../db/migrations/20261106010000_management_authority.sql");

pub(crate) const CATALOG_OWNER_ROLES: [&str; 2] = [
    "aegaeon_subject_owner",
    "aegaeon_management_authority_owner",
];

fn security_catalog_migration() -> &'static str {
    MANAGEMENT_MIGRATION
}

fn compiled_function_owner(name: &str) -> &'static str {
    if MANAGEMENT_MIGRATION
        .split("CREATE FUNCTION management_authority.")
        .skip(1)
        .any(|definition| {
            definition
                .split_once('(')
                .is_some_and(|(candidate, _)| candidate == name)
        })
    {
        "aegaeon_management_authority_owner"
    } else {
        "aegaeon_subject_owner"
    }
}
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
        (FORWARD_MIGRATION, "CREATE OR REPLACE FUNCTION aegaeon."),
        (ATTRIBUTE_MIGRATION, "CREATE OR REPLACE FUNCTION aegaeon."),
        (LTI_MIGRATION, "CREATE OR REPLACE FUNCTION aegaeon."),
        (
            crate::organization_schema::component!("organization_identity_generation"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("organization_identity_enrollment"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("organization_support_policy"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("organization_admin_access"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("organization_snapshot_history"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("organization_import_target"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("organization_inactive_import"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("identity_creation_receipts"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("organization_prepared_inspection"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("subject_history_restoration"),
            "CREATE FUNCTION aegaeon.",
        ),
        (
            crate::organization_schema::component!("catalog"),
            "CREATE OR REPLACE FUNCTION aegaeon.",
        ),
        (
            MANAGEMENT_MIGRATION,
            "CREATE FUNCTION management_authority.",
        ),
        (
            security_catalog_migration(),
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
        + CATALOG_OWNER_ROLES.len())
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
            || owner != Some(compiled_function_owner(name))
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

pub(super) fn physical_contract_hash() -> Result<String, HistoryInputError> {
    fn literal(marker: &str, terminator: &str) -> Result<Value, HistoryInputError> {
        let text = security_catalog_migration()
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

    #[test]
    fn physical_catalog_revision_names_and_hashes_match_atlas_manifest() {
        let literal = security_catalog_migration()
            .split_once("$revisions$")
            .unwrap()
            .1
            .split_once("$revisions$")
            .unwrap()
            .0;
        let rows: Vec<Value> = serde_json::from_str(literal).unwrap();
        let entries: Vec<_> = ATLAS_SUM.lines().skip(1).collect();
        assert_eq!(rows.len(), entries.len());
        for (row, entry) in rows.iter().zip(entries) {
            let (name, hash) = entry.split_once(' ').unwrap();
            let (version, description) =
                name.strip_suffix(".sql").unwrap().split_once('_').unwrap();
            assert_eq!(row["version"], version);
            assert_eq!(row["description"], description);
            if row["sha256_base64"].is_null() {
                assert_eq!(row, rows.last().unwrap());
            } else {
                assert_eq!(row["sha256_base64"], hash.strip_prefix("h1:").unwrap());
            }
        }
    }
}
