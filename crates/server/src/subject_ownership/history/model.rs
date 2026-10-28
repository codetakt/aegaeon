//! Closed version-one documents. Parsing these types alone is not adoption.
use serde::{Deserialize, Deserializer, Serialize};

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub environment_id: String,
    pub issuer_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub deployment_id: String,
    pub runtime_role: String,
    pub database_name: String,
    pub database_oid: u64,
    pub server_version_num: u64,
    pub server_encoding: String,
    pub schema_revision: String,
    pub schema_sha256: String,
    pub catalog_sha256: String,
    pub tool_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    pub source_commit: Option<String>,
    pub source_tree: String,
    #[serde(deserialize_with = "required_nullable")]
    pub dirty_input_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryBinding {
    pub artifact_sha256: String,
    pub state_sha256: String,
    pub findings_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    CurrentSnapshot,
    AuditSnapshot,
    ExternalJournal,
    RetainedBackup,
    Reconstruction,
    InvalidHistoryEvidence,
    CompletenessAttestation,
}
impl SourceKind {
    pub fn supports_reconstruction(self) -> bool {
        matches!(
            self,
            Self::ExternalJournal | Self::RetainedBackup | Self::Reconstruction
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub source_id: String,
    pub kind: SourceKind,
    pub sha256: String,
    pub byte_length: u64,
    pub private_reference: String,
    pub provenance_reference: String,
    pub environment_ids: Vec<String>,
    pub coverage_start_reference: String,
    pub coverage_end_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub owner_id: String,
    pub environment_id: String,
    pub source_refs: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub subject: String,
    pub owner_id: String,
    pub source_refs: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidHistory {
    pub observation_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub owner_id: Option<String>,
    pub evidence_source: String,
    pub source_refs: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectOwner {
    pub subject: String,
    pub owner_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Resolution {
    ReconstructedOwnership {
        finding_id: String,
        source_refs: Vec<String>,
        review_reference: String,
        owners: Vec<String>,
        subjects: Vec<SubjectOwner>,
    },
    OutsideTarget {
        finding_id: String,
        source_refs: Vec<String>,
        review_reference: String,
        environment_id: String,
    },
    NoOwnershipEffect {
        finding_id: String,
        source_refs: Vec<String>,
        review_reference: String,
    },
    InvalidDisclosureRetained {
        finding_id: String,
        source_refs: Vec<String>,
        review_reference: String,
        observation_id: String,
        #[serde(deserialize_with = "required_nullable")]
        owner_id: Option<String>,
        evidence_source: String,
    },
}
impl Resolution {
    pub fn common(&self) -> (&str, &[String], &str) {
        match self {
            Self::ReconstructedOwnership {
                finding_id,
                source_refs,
                review_reference,
                ..
            }
            | Self::OutsideTarget {
                finding_id,
                source_refs,
                review_reference,
                ..
            }
            | Self::NoOwnershipEffect {
                finding_id,
                source_refs,
                review_reference,
            }
            | Self::InvalidDisclosureRetained {
                finding_id,
                source_refs,
                review_reference,
                ..
            } => (finding_id, source_refs, review_reference),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completeness {
    pub assertion: String,
    pub namespace_start_reference: String,
    pub coverage_end_reference: String,
    pub complete_valid_subject_history: bool,
    pub complete_owner_uuid_history: bool,
    pub owner_uuid_environment_bindings_complete: bool,
    pub sources_exhaustive: bool,
    pub unresolved_findings: u64,
    pub asserted_by: String,
    pub authority_reference: String,
    pub attestation_source: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub version: u64,
    pub receipt_id: String,
    pub namespace: Namespace,
    pub target: Target,
    pub inventory: InventoryBinding,
    pub sources: Vec<Source>,
    pub owners: Vec<Owner>,
    pub reservations: Vec<Reservation>,
    pub invalid_history: Vec<InvalidHistory>,
    pub resolutions: Vec<Resolution>,
    pub completeness: Completeness,
    pub maintenance_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub name: String,
    pub count: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactOrigin {
    CurrentUser,
    PermanentOwner,
    PermanentReservation,
    ManagementCreateSubject,
    ManagementPreviousSubject,
    ManagementCurrentSubject,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub fact_id: String,
    pub origin: FactOrigin,
    pub row_key: String,
    pub row_sha256: String,
    pub environment_id: String,
    pub owner_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub subject: Option<String>,
    pub valid: bool,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingClass {
    UnknownEvent,
    MalformedEvent,
    UnknownOwner,
    UnscopedEvent,
    InvalidHistory,
    OwnershipConflict,
    OutsideTarget,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub finding_id: String,
    pub class: FindingClass,
    pub origin: String,
    pub row_key: String,
    pub row_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    pub environment_id: Option<String>,
    pub observed_owner_ids: Vec<String>,
    pub observed_subjects: Vec<String>,
    pub preserved_fact_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub format: String,
    pub version: u64,
    pub namespace: Namespace,
    pub target: Target,
    pub collections: Vec<Collection>,
    pub state_sha256: String,
    pub facts: Vec<Fact>,
    pub findings: Vec<Finding>,
    pub findings_sha256: String,
}

/// Labels from a retained, reviewed source/build record. The executable hash is
/// verified by the CLI; source review/signature authority remains external.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSourceIdentity {
    pub tool_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    pub source_commit: Option<String>,
    pub source_tree: String,
    #[serde(deserialize_with = "required_nullable")]
    pub dirty_input_sha256: Option<String>,
}
