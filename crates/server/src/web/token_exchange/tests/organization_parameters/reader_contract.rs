use std::collections::BTreeSet;

use crate::application_authorization::inorii::OrganizationRole;
use serde::Deserialize;

use super::TestResult;

const SOURCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec/application-membership-reader-contract.json"
));

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReaderContract {
    version: u8,
    scope: Scope,
    relations: Vec<Relation>,
    joins: [[String; 2]; 2],
    predicates: Predicates,
    semantics: Vec<Semantics>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    ReaderCompatibility,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Relation {
    name: String,
    columns: Vec<Column>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Column {
    name: String,
    capability: Capability,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Capability {
    ExactBoundText,
    UserJoinKey,
    OrganizationJoinKey,
    CanonicalUuidText,
    NullDeletionMarker,
    RoleText,
    ActiveStatusComparison,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Predicates {
    active_status: String,
    role_labels: [OrganizationRole; 2],
    organization_identifier_prefix: String,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Semantics {
    RelationsResolveInTrustedReaderSearchPath,
    IssuerAndSubjectCompareToExactBoundValues,
    JoinKeysRequireCompatibleEquality,
    PublicIdTextIsCanonicalLowercaseHyphenatedUuid,
    NullComparisonAndJoinInputsDoNotMatch,
    NullPublicIdOrStatusDoesNotMatch,
    NullSelectedRoleIsLookupError,
    NullDeletedAtMeansNotDeleted,
    AllMatchingBindingsSupplyUnion,
}

fn supported_column(relation: &str, column: &str) -> Option<Capability> {
    use Capability::{
        ActiveStatusComparison, CanonicalUuidText, ExactBoundText, NullDeletionMarker,
        OrganizationJoinKey, RoleText, UserJoinKey,
    };
    match (relation, column) {
        ("authorization_subject_bindings", "issuer" | "subject") => Some(ExactBoundText),
        ("authorization_subject_bindings" | "organization_users", "user_id") => Some(UserJoinKey),
        ("organizations", "id") | ("organization_users", "organization_id") => {
            Some(OrganizationJoinKey)
        }
        ("organizations", "public_id") => Some(CanonicalUuidText),
        ("organizations", "deleted_at") => Some(NullDeletionMarker),
        ("organization_users", "role") => Some(RoleText),
        ("organization_users", "status") => Some(ActiveStatusComparison),
        _ => None,
    }
}

// These concrete types are a finite PostgreSQL test witness. The reader contract
// requires operations and compatible joins, not bigint/uuid/timestamptz storage.
fn witness_type(capability: Capability) -> &'static str {
    match capability {
        Capability::UserJoinKey | Capability::OrganizationJoinKey => "bigint",
        Capability::CanonicalUuidText => "uuid",
        Capability::NullDeletionMarker => "timestamptz",
        Capability::ExactBoundText | Capability::RoleText | Capability::ActiveStatusComparison => {
            "text"
        }
    }
}

impl ReaderContract {
    pub(super) fn load() -> TestResult<Self> {
        Self::parse(SOURCE)
    }

    fn parse(source: &str) -> TestResult<Self> {
        let contract: Self = serde_json::from_str(source)?;
        if contract.version != 1
            || !matches!(contract.scope, Scope::ReaderCompatibility)
            || contract.relations.len() != 3
            || contract.semantics.len() != 9
            || contract.semantics.iter().collect::<BTreeSet<_>>().len() != 9
            || contract.predicates.active_status != "active"
            || contract.predicates.role_labels
                != [
                    OrganizationRole::OrganizationAdmin,
                    OrganizationRole::OrganizationStaff,
                ]
            || contract.predicates.organization_identifier_prefix != "organization_"
        {
            return Err("unsupported membership reader contract".into());
        }
        contract.fixture_ddl()?;
        let mut groups = BTreeSet::new();
        for [left, right] in &contract.joins {
            let parse_key = |key: &str| {
                key.split_once('.')
                    .and_then(|(table, column)| supported_column(table, column))
            };
            let capability = parse_key(left).ok_or("unsupported reader join")?;
            if left == right
                || parse_key(right) != Some(capability)
                || !matches!(
                    capability,
                    Capability::UserJoinKey | Capability::OrganizationJoinKey
                )
                || !groups.insert(capability)
            {
                return Err("incompatible or duplicate reader join".into());
            }
        }
        Ok(contract)
    }

    pub(super) fn fixture_ddl(&self) -> TestResult<String> {
        let mut relations = BTreeSet::new();
        let mut ddl = String::new();
        for relation in &self.relations {
            let expected_columns = match relation.name.as_str() {
                "authorization_subject_bindings" | "organizations" => 3,
                "organization_users" => 4,
                _ => return Err("unsupported fixture relation".into()),
            };
            if !relations.insert(&relation.name) || relation.columns.len() != expected_columns {
                return Err("duplicate relation or missing required columns".into());
            }
            let mut names = BTreeSet::new();
            let mut columns = Vec::new();
            for column in &relation.columns {
                if supported_column(&relation.name, &column.name) != Some(column.capability)
                    || !names.insert(&column.name)
                {
                    return Err("unsupported or duplicate fixture column".into());
                }
                // Only the supported vocabulary above can reach these quoted identifiers.
                columns.push(format!(
                    "\"{}\" {}",
                    column.name,
                    witness_type(column.capability)
                ));
            }
            ddl.push_str(&format!(
                "CREATE TABLE \"{}\" ({});\n",
                relation.name,
                columns.join(", ")
            ));
        }
        Ok(ddl)
    }

    pub(super) fn active_status(&self) -> &str {
        &self.predicates.active_status
    }

    pub(super) fn role_labels(&self) -> TestResult<[String; 2]> {
        Ok(serde_json::from_value(serde_json::to_value(
            self.predicates.role_labels,
        )?)?)
    }
}

#[test]
fn reader_contract_rejects_unsupported_and_incomplete_inputs() -> TestResult {
    ReaderContract::load()?;
    let original: serde_json::Value = serde_json::from_str(SOURCE)?;
    let controls: [fn(&mut serde_json::Value); 13] = [
        |v: &mut serde_json::Value| v["version"] = 2.into(),
        |v: &mut serde_json::Value| v["unexpected"] = true.into(),
        |v: &mut serde_json::Value| {
            v.as_object_mut().unwrap().remove("joins");
        },
        |v: &mut serde_json::Value| v["relations"][0]["unexpected"] = true.into(),
        |v: &mut serde_json::Value| v["relations"][0]["columns"][0]["name"] = "issuer\";".into(),
        |v: &mut serde_json::Value| {
            v["relations"][0]["columns"][0]["capability"] = "integer".into()
        },
        |v: &mut serde_json::Value| {
            v["relations"][0]["columns"][1] = v["relations"][0]["columns"][0].clone()
        },
        |v: &mut serde_json::Value| v["joins"][1] = v["joins"][0].clone(),
        |v: &mut serde_json::Value| v["semantics"][1] = v["semantics"][0].clone(),
        |v: &mut serde_json::Value| v["predicates"]["active_status"] = "enabled".into(),
        |v: &mut serde_json::Value| {
            v["predicates"]["role_labels"][1] = v["predicates"]["role_labels"][0].clone()
        },
        |v: &mut serde_json::Value| {
            v["predicates"]["role_labels"] =
                serde_json::json!(["ORGANIZATION_STAFF", "ORGANIZATION_ADMIN"])
        },
        |v: &mut serde_json::Value| {
            v["predicates"]["organization_identifier_prefix"] = "org_".into()
        },
    ];
    for mutate in controls {
        let mut invalid = original.clone();
        mutate(&mut invalid);
        assert!(ReaderContract::parse(&invalid.to_string()).is_err());
    }
    Ok(())
}
