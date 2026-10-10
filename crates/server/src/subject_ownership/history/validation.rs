use super::digest::{hex_digest, metadata_text};
use super::model::*;
use super::{content_id, frame, parse_strict, sha256_hex, HashChain, HistoryInputError};
use std::collections::{HashMap, HashSet};

pub const MANIFEST_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const INVENTORY_MAX_BYTES: usize = 256 * 1024 * 1024;
pub const COLLECTIONS: [&str; 8] = [
    "environments",
    "subject_ownership_namespaces",
    "subject_ownership_adoptions",
    "end_user_identity_owners",
    "end_user_subject_reservations",
    "end_users",
    "audit_events",
    "physical_catalog",
];

type Result<T> = std::result::Result<T, HistoryInputError>;
fn require(condition: bool, error: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(HistoryInputError(error.into()))
    }
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn reference(value: &str) -> bool {
    (1..=1024).contains(&value.len()) && value.bytes().all(|b| (32..=126).contains(&b))
}
pub(super) fn subject(value: &str) -> bool {
    (1..=255).contains(&value.len()) && value.is_ascii() && !value.contains('\0')
}
fn unique(values: &[String]) -> bool {
    values.iter().collect::<HashSet<_>>().len() == values.len()
}
fn namespace(value: &Namespace) -> Result<()> {
    require(
        uuid(&value.environment_id)
            && !value.issuer_host.is_empty()
            && !value.issuer_host.contains('\0'),
        "invalid namespace",
    )
}
fn target(value: &Target) -> Result<()> {
    require(
        identifier(&value.deployment_id)
            && (1..=63).contains(&value.runtime_role.len())
            && (1..=63).contains(&value.database_name.len())
            && value.database_oid <= u64::from(u32::MAX)
            && value.database_oid != 0
            && value.server_version_num <= i64::MAX as u64
            && value.server_version_num != 0
            && value.server_encoding == "UTF8"
            && identifier(&value.schema_revision)
            && hex(&value.schema_sha256, 64)
            && hex(&value.catalog_sha256, 64)
            && hex(&value.tool_sha256, 64)
            && hex(&value.source_tree, 40)
            && value.source_commit.as_ref().is_none_or(|v| hex(v, 40))
            && value.dirty_input_sha256.as_ref().is_none_or(|v| hex(v, 64))
            && (value.source_commit.is_some() || value.dirty_input_sha256.is_some()),
        "invalid target or build provenance",
    )
}

/// Parse the exact raw manifest and validate its closed grammar and source graph.
/// External completeness and source authenticity remain operator premises.
/// # Errors
/// Refuses unsupported syntax, domains, duplicate identities and missing evidence.
pub fn parse_manifest(raw: &[u8]) -> Result<Manifest> {
    let value = parse_strict(raw, MANIFEST_MAX_BYTES)?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|_| HistoryInputError("manifest shape violation".into()))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(m: &Manifest) -> Result<()> {
    require(
        m.format == "aegaeon-subject-ownership-adoption" && m.version == 1 && uuid(&m.receipt_id),
        "unsupported manifest identity",
    )?;
    namespace(&m.namespace)?;
    target(&m.target)?;
    require(
        hex(&m.inventory.artifact_sha256, 64)
            && hex(&m.inventory.state_sha256, 64)
            && hex(&m.inventory.findings_sha256, 64),
        "invalid inventory binding",
    )?;
    require(
        reference(&m.maintenance_reference),
        "invalid maintenance reference",
    )?;
    require(
        m.sources.len() <= 256
            && m.owners.len()
                + m.reservations.len()
                + m.invalid_history.len()
                + m.resolutions.len()
                <= 1_000_000,
        "manifest entry limit",
    )?;
    let mut sources = HashMap::new();
    for source in &m.sources {
        require(
            identifier(&source.source_id)
                && hex(&source.sha256, 64)
                && source.byte_length <= i64::MAX as u64
                && reference(&source.private_reference)
                && reference(&source.provenance_reference)
                && reference(&source.coverage_start_reference)
                && reference(&source.coverage_end_reference)
                && !source.environment_ids.is_empty()
                && unique(&source.environment_ids)
                && source.environment_ids.iter().all(|id| uuid(id)),
            "invalid source",
        )?;
        require(
            sources.insert(source.source_id.as_str(), source).is_none(),
            "duplicate source identity",
        )?;
    }
    let refs = |values: &[String], env: &str, reconstruct: bool| -> Result<()> {
        require(
            (1..=256).contains(&values.len()) && unique(values),
            "invalid source references",
        )?;
        let mut external = false;
        for id in values {
            let source = sources
                .get(id.as_str())
                .ok_or_else(|| HistoryInputError("unknown source reference".into()))?;
            require(
                source.environment_ids.iter().any(|e| e == env),
                "source does not cover asserted environment",
            )?;
            external |= source.kind.supports_reconstruction() && source.byte_length > 0;
        }
        require(
            !reconstruct || external,
            "external reconstruction evidence required",
        )
    };
    let ownership = validate_manifest_entries(m, &sources, &refs)?;
    validate_manifest_resolutions(m, &ownership, &refs)?;
    validate_completeness(m, &sources)
}

struct ManifestOwnership<'a> {
    owners: HashSet<&'a str>,
    reservations: HashMap<&'a str, &'a str>,
    invalids: HashMap<&'a str, &'a InvalidHistory>,
}

fn validate_manifest_entries<'a>(
    m: &'a Manifest,
    sources: &HashMap<&str, &Source>,
    refs: &impl Fn(&[String], &str, bool) -> Result<()>,
) -> Result<ManifestOwnership<'a>> {
    let target_env = &m.namespace.environment_id;
    let mut owners = HashSet::new();
    for owner in &m.owners {
        require(
            uuid(&owner.owner_id)
                && owner.environment_id == *target_env
                && owners.insert(owner.owner_id.as_str()),
            "invalid or duplicate owner",
        )?;
        refs(&owner.source_refs, target_env, false)?;
    }
    let mut reservations = HashMap::new();
    for reservation in &m.reservations {
        require(
            subject(&reservation.subject)
                && owners.contains(reservation.owner_id.as_str())
                && reservations
                    .insert(reservation.subject.as_str(), reservation.owner_id.as_str())
                    .is_none(),
            "invalid or duplicate reservation",
        )?;
        refs(&reservation.source_refs, target_env, false)?;
    }
    let mut invalids = HashMap::new();
    for invalid in &m.invalid_history {
        require(
            hex(&invalid.observation_id, 64)
                && invalid
                    .owner_id
                    .as_ref()
                    .is_none_or(|id| owners.contains(id.as_str()))
                && invalids
                    .insert(invalid.observation_id.as_str(), invalid)
                    .is_none(),
            "invalid historical observation",
        )?;
        refs(&invalid.source_refs, target_env, false)?;
        require(
            invalid.source_refs.contains(&invalid.evidence_source)
                && sources
                    .get(invalid.evidence_source.as_str())
                    .is_some_and(|s| {
                        s.kind == SourceKind::InvalidHistoryEvidence && s.byte_length > 0
                    }),
            "invalid disclosure evidence required",
        )?;
    }
    Ok(ManifestOwnership {
        owners,
        reservations,
        invalids,
    })
}

fn validate_manifest_resolutions(
    m: &Manifest,
    ownership: &ManifestOwnership<'_>,
    refs: &impl Fn(&[String], &str, bool) -> Result<()>,
) -> Result<()> {
    let target_env = &m.namespace.environment_id;
    let ManifestOwnership {
        owners,
        reservations,
        invalids,
    } = ownership;
    let mut resolutions = HashSet::new();
    for resolution in &m.resolutions {
        let (id, source_refs, review) = resolution.common();
        require(
            hex(id, 64) && resolutions.insert(id) && reference(review),
            "invalid or duplicate resolution",
        )?;
        let env = match resolution {
            Resolution::OutsideTarget { environment_id, .. } => environment_id,
            _ => target_env,
        };
        refs(source_refs, env, true)?;
        match resolution {
            Resolution::ReconstructedOwnership {
                owners: reconstructed,
                subjects,
                ..
            } => {
                require(
                    unique(reconstructed)
                        && (!reconstructed.is_empty() || !subjects.is_empty())
                        && reconstructed.iter().all(|id| owners.contains(id.as_str())),
                    "invalid reconstructed owners",
                )?;
                let mut pairs = HashSet::new();
                for pair in subjects {
                    require(
                        pairs.insert((&pair.subject, &pair.owner_id))
                            && reservations.get(pair.subject.as_str())
                                == Some(&pair.owner_id.as_str()),
                        "reconstruction missing from ownership union",
                    )?;
                }
            }
            Resolution::OutsideTarget { environment_id, .. } => require(
                uuid(environment_id) && environment_id != target_env,
                "invalid outside-target resolution",
            )?,
            Resolution::InvalidDisclosureRetained {
                observation_id,
                owner_id,
                evidence_source,
                ..
            } => {
                let invalid = invalids
                    .get(observation_id.as_str())
                    .ok_or_else(|| HistoryInputError("unretained invalid disclosure".into()))?;
                require(
                    invalid.owner_id == *owner_id
                        && invalid.evidence_source == *evidence_source
                        && source_refs.contains(evidence_source),
                    "invalid disclosure resolution mismatch",
                )?;
            }
            Resolution::NoOwnershipEffect { .. } => (),
        }
    }
    Ok(())
}

fn validate_completeness(m: &Manifest, sources: &HashMap<&str, &Source>) -> Result<()> {
    let target_env = &m.namespace.environment_id;
    let c = &m.completeness;
    require(
        c.assertion == "complete-history-for-this-namespace"
            && c.complete_valid_subject_history
            && c.complete_owner_uuid_history
            && c.owner_uuid_environment_bindings_complete
            && c.sources_exhaustive
            && c.unresolved_findings == 0
            && reference(&c.namespace_start_reference)
            && reference(&c.coverage_end_reference)
            && reference(&c.asserted_by)
            && reference(&c.authority_reference),
        "complete-history assertion required",
    )?;
    require(
        m.sources
            .iter()
            .filter(|s| s.kind == SourceKind::CompletenessAttestation)
            .count()
            == 1
            && sources.get(c.attestation_source.as_str()).is_some_and(|s| {
                s.kind == SourceKind::CompletenessAttestation
                    && s.byte_length > 0
                    && s.environment_ids.contains(target_env)
            }),
        "one retained completeness attestation required",
    )?;
    Ok(())
}

/// Parse an inventory artifact. Digests must additionally be compared with the
/// independently collected, locked database state before adoption.
/// # Errors
/// Refuses malformed or unordered facts, findings, collection identities or domains.
pub fn parse_inventory(raw: &[u8]) -> Result<Inventory> {
    let value = parse_strict(raw, INVENTORY_MAX_BYTES)?;
    let inventory: Inventory = serde_json::from_value(value)
        .map_err(|_| HistoryInputError("inventory shape violation".into()))?;
    require(
        inventory.format == "aegaeon-subject-ownership-inventory" && inventory.version == 1,
        "unsupported inventory version",
    )?;
    namespace(&inventory.namespace)?;
    target(&inventory.target)?;
    require(
        hex(&inventory.state_sha256, 64)
            && hex(&inventory.findings_sha256, 64)
            && inventory.collections.len() == COLLECTIONS.len(),
        "invalid inventory digest domain",
    )?;
    for (collection, expected) in inventory.collections.iter().zip(COLLECTIONS) {
        require(
            collection.name == expected
                && collection.count <= i64::MAX as u64
                && hex(&collection.sha256, 64),
            "invalid ordered collection",
        )?;
    }
    let mut facts = HashMap::new();
    let mut previous = "";
    for fact in &inventory.facts {
        require(
            hex(&fact.fact_id, 64)
                && fact.fact_id.as_str() > previous
                && hex(&fact.row_sha256, 64)
                && !fact.row_key.is_empty()
                && uuid(&fact.environment_id)
                && uuid(&fact.owner_id),
            "invalid ordered fact",
        )?;
        require(
            fact.subject
                .as_ref()
                .is_none_or(|s| fact.valid == subject(s)),
            "incorrect subject validity",
        )?;
        require(
            fact.subject.is_some() || !fact.valid,
            "UUID-only fact cannot assert valid subject",
        )?;
        previous = &fact.fact_id;
        facts.insert(fact.fact_id.as_str(), fact);
    }
    previous = "";
    for finding in &inventory.findings {
        require(
            hex(&finding.finding_id, 64)
                && finding.finding_id.as_str() > previous
                && hex(&finding.row_sha256, 64)
                && !finding.row_key.is_empty()
                && finding.environment_id.as_ref().is_none_or(|id| uuid(id))
                && unique(&finding.observed_owner_ids)
                && unique(&finding.observed_subjects)
                && unique(&finding.preserved_fact_ids)
                && finding
                    .preserved_fact_ids
                    .iter()
                    .all(|id| facts.contains_key(id.as_str())),
            "invalid ordered finding",
        )?;
        previous = &finding.finding_id;
    }
    validate_inventory_digests(&inventory)?;
    Ok(inventory)
}

/// Validate preservation and resolution rules against an independently validated
/// inventory. The SQL adoption function repeats these checks against live facts.
/// # Errors
/// Refuses omissions, actual ownership conflicts and inadmissible resolutions.
pub fn validate_union(
    m: &Manifest,
    inventory: &Inventory,
    inventory_raw_sha256: &str,
) -> Result<()> {
    validate_manifest(m)?;
    require(
        m.namespace == inventory.namespace
            && m.target == inventory.target
            && m.inventory.artifact_sha256 == inventory_raw_sha256
            && m.inventory.state_sha256 == inventory.state_sha256
            && m.inventory.findings_sha256 == inventory.findings_sha256,
        "manifest and inventory binding mismatch",
    )?;
    let target = &m.namespace.environment_id;
    let owners: HashSet<_> = m.owners.iter().map(|o| o.owner_id.as_str()).collect();
    let reservations: HashMap<_, _> = m
        .reservations
        .iter()
        .map(|r| (r.subject.as_str(), r.owner_id.as_str()))
        .collect();
    validate_known_facts(inventory, target, &owners, &reservations)?;
    require(
        m.invalid_history.iter().all(|i| i.owner_id.is_some()),
        "invalid history owner remains unresolved",
    )?;
    let fact_index: HashMap<_, _> = inventory
        .facts
        .iter()
        .map(|f| (f.fact_id.as_str(), f))
        .collect();
    let mut resolutions: HashMap<_, _> = m.resolutions.iter().map(|r| (r.common().0, r)).collect();
    for finding in &inventory.findings {
        require(
            finding.class != FindingClass::OwnershipConflict,
            "ownership conflict cannot be waived",
        )?;
        let observes_claimed_owner = finding
            .observed_owner_ids
            .iter()
            .any(|id| owners.contains(id.as_str()));
        let claimed_outside =
            finding.class == FindingClass::OutsideTarget && observes_claimed_owner;
        let resolution = resolutions.remove(finding.finding_id.as_str());
        if finding.class == FindingClass::OutsideTarget && !claimed_outside {
            require(resolution.is_none(), "unused outside-target resolution")?;
            continue;
        }
        let resolution =
            resolution.ok_or_else(|| HistoryInputError("unresolved inventory finding".into()))?;
        if claimed_outside {
            require(
                matches!(resolution, Resolution::ReconstructedOwnership { .. }),
                "outside-target claimed UUID requires binding reconstruction",
            )?;
        }
        validate_finding_resolution(
            finding,
            resolution,
            target,
            &fact_index,
            observes_claimed_owner,
        )?;
    }
    require(resolutions.is_empty(), "unused resolution")
}

fn validate_known_facts(
    inventory: &Inventory,
    target: &str,
    owners: &HashSet<&str>,
    reservations: &HashMap<&str, &str>,
) -> Result<()> {
    let mut global_owners = HashMap::new();
    let mut global_subjects = HashMap::new();
    for fact in &inventory.facts {
        if let Some(prior) = global_owners.insert(&fact.owner_id, &fact.environment_id) {
            require(
                prior == &fact.environment_id,
                "known global UUID environment conflict",
            )?;
        }
        require(
            !owners.contains(fact.owner_id.as_str()) || fact.environment_id == *target,
            "claimed UUID is known in another environment",
        )?;
        if fact.environment_id == *target {
            require(
                owners.contains(fact.owner_id.as_str()),
                "known owner omitted from union",
            )?;
        }
        if let Some(subject) = &fact.subject {
            if fact.valid {
                if let Some(prior) =
                    global_subjects.insert((&fact.environment_id, subject), &fact.owner_id)
                {
                    require(
                        fact.environment_id != *target || prior == &fact.owner_id,
                        "known different-owner subject conflict",
                    )?;
                }
                if fact.environment_id == *target {
                    require(
                        reservations.get(subject.as_str()) == Some(&fact.owner_id.as_str()),
                        "known subject ownership omitted from union",
                    )?;
                }
            } else {
                require(
                    !matches!(
                        fact.origin,
                        FactOrigin::CurrentUser | FactOrigin::PermanentReservation
                    ),
                    "invalid current or permanent subject",
                )?;
            }
        }
    }
    Ok(())
}

fn validate_reconstructed_finding(
    finding: &Finding,
    reconstructed: &[String],
    subjects: &[SubjectOwner],
    target: &str,
    fact_index: &HashMap<&str, &Fact>,
) -> Result<()> {
    require(
        finding.class != FindingClass::InvalidHistory,
        "invalid disclosure requires retained evidence",
    )?;
    for known in &finding.observed_subjects {
        if subject(known) && matches!(finding.class, FindingClass::UnknownOwner) {
            require(
                subjects.iter().any(|s| &s.subject == known),
                "known subject-only observation lacks reconstructed owner",
            )?;
        }
    }
    for id in &finding.preserved_fact_ids {
        let fact = fact_index
            .get(id.as_str())
            .ok_or_else(|| HistoryInputError("missing preserved fact".into()))?;
        if fact.environment_id == *target {
            require(
                reconstructed.contains(&fact.owner_id)
                    || subjects.iter().any(|s| s.owner_id == fact.owner_id),
                "reconstruction omitted preserved owner",
            )?;
            if let Some(value) = fact.subject.as_ref().filter(|_| fact.valid) {
                require(
                    subjects
                        .iter()
                        .any(|s| &s.subject == value && s.owner_id == fact.owner_id),
                    "reconstruction omitted preserved subject",
                )?;
            }
        }
    }
    Ok(())
}

fn validate_finding_resolution(
    finding: &Finding,
    resolution: &Resolution,
    target: &str,
    fact_index: &HashMap<&str, &Fact>,
    observes_claimed_owner: bool,
) -> Result<()> {
    match resolution {
        Resolution::ReconstructedOwnership {
            owners: reconstructed,
            subjects,
            ..
        } => {
            validate_reconstructed_finding(finding, reconstructed, subjects, target, fact_index)?;
        }
        Resolution::OutsideTarget { environment_id, .. } => {
            require(
                finding
                    .environment_id
                    .as_ref()
                    .is_none_or(|id| id == environment_id)
                    && finding.preserved_fact_ids.iter().all(|id| {
                        fact_index
                            .get(id.as_str())
                            .is_some_and(|f| &f.environment_id == environment_id)
                    }),
                "outside-target classification relocates known fact",
            )?;
            require(
                !observes_claimed_owner,
                "outside classification cannot clear claimed UUID binding",
            )?;
        }
        Resolution::NoOwnershipEffect { .. } => {
            require(
                finding.preserved_fact_ids.is_empty()
                    && !matches!(
                        finding.class,
                        FindingClass::UnknownOwner | FindingClass::InvalidHistory
                    )
                    && !identity_event(&finding.origin),
                "ownership-bearing observation cannot be dismissed",
            )?;
        }
        Resolution::InvalidDisclosureRetained {
            owner_id,
            observation_id,
            ..
        } => {
            require(
                finding.class == FindingClass::InvalidHistory
                    && owner_id.is_some()
                    && finding.observed_subjects.len() == 1
                    && finding.observed_subjects.iter().all(|s| !subject(s)),
                "valid or unresolved disclosure cannot be classified invalid",
            )?;
            require(
                finding.preserved_fact_ids.iter().all(|id| {
                    fact_index.get(id.as_str()).is_some_and(|fact| {
                        fact.environment_id != *target || Some(&fact.owner_id) == owner_id.as_ref()
                    })
                }),
                "invalid disclosure owner contradicts known owner",
            )?;
            let observed_hash = sha256_hex(&frame(finding.observed_subjects[0].as_bytes()));
            let expected_observation = content_id(
                "aegaeon-invalid-subject-v1",
                &[
                    ("origin", Some(&finding.origin)),
                    ("row_key", Some(&finding.row_key)),
                    ("sha256", Some(&finding.row_sha256)),
                    ("sha256", Some(&observed_hash)),
                ],
            );
            require(
                *observation_id == expected_observation,
                "invalid observation identity mismatch",
            )?;
        }
    }
    Ok(())
}

fn identity_event(origin: &str) -> bool {
    matches!(
        origin,
        "management.user.created.v1"
            | "management.user.invited.v1"
            | "management.user.imported.v1"
            | "management.user.updated.v1"
            | "management.user.deleted.v1"
            | "management.user.restored.v1"
            | "management.user.suspended.v1"
            | "management.user.reactivated.v1"
            | "upstream.user.provision.authorized.v1"
    )
}

fn enum_text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .expect("enum serialization")
        .as_str()
        .expect("string enum")
        .to_owned()
}

fn validate_inventory_digests(inventory: &Inventory) -> Result<()> {
    let mut state = HashChain::new("state");
    for collection in &inventory.collections {
        let value = serde_json::to_value(collection).expect("collection serialization");
        state
            .push(&collection.name, metadata_text(&value).as_bytes())
            .map_err(|e| HistoryInputError(e.into()))?;
    }
    require(
        hex_digest(&state.finish().1) == inventory.state_sha256,
        "inventory state digest mismatch",
    )?;
    require(
        inventory
            .collections
            .last()
            .is_some_and(|c| c.sha256 == inventory.target.catalog_sha256),
        "catalog binding mismatch",
    )?;
    for fact in &inventory.facts {
        let origin = enum_text(&fact.origin);
        let valid = if fact.valid { "true" } else { "false" };
        let id = content_id(
            "aegaeon-subject-fact-v1",
            &[
                ("origin", Some(&origin)),
                ("row_key", Some(&fact.row_key)),
                ("sha256", Some(&fact.row_sha256)),
                ("uuid", Some(&fact.environment_id)),
                ("uuid", Some(&fact.owner_id)),
                ("text", fact.subject.as_deref()),
                ("boolean", Some(valid)),
            ],
        );
        require(id == fact.fact_id, "fact content ID mismatch")?;
    }
    let mut findings = HashChain::new("findings");
    for finding in &inventory.findings {
        let class = enum_text(&finding.class);
        let id = content_id(
            "aegaeon-subject-finding-v1",
            &[
                ("class", Some(&class)),
                ("origin", Some(&finding.origin)),
                ("row_key", Some(&finding.row_key)),
                ("sha256", Some(&finding.row_sha256)),
            ],
        );
        require(id == finding.finding_id, "finding content ID mismatch")?;
        let value = serde_json::to_value(finding).expect("finding serialization");
        findings
            .push(&finding.finding_id, metadata_text(&value).as_bytes())
            .map_err(|e| HistoryInputError(e.into()))?;
    }
    require(
        hex_digest(&findings.finish().1) == inventory.findings_sha256,
        "findings digest mismatch",
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::{json, Value};
    const ENVIRONMENT: &str = "30000000-0000-0000-0000-000000000001";
    const OWNER: &str = "40000000-0000-0000-0000-000000000001";

    pub(crate) fn manifest() -> Value {
        json!({"format":"aegaeon-subject-ownership-adoption","version":1,
            "receipt_id":"50000000-0000-0000-0000-000000000001",
            "namespace":{"environment_id":ENVIRONMENT,"issuer_host":"issuer.example.com"},
            "target":{"deployment_id":"test","runtime_role":"runtime","database_name":"test","database_oid":42,
                "server_version_num":180001,"server_encoding":"UTF8","schema_revision":"20261002130000",
                "schema_sha256":"a".repeat(64),"catalog_sha256":"b".repeat(64),"tool_sha256":"c".repeat(64),
                "source_commit":null,"source_tree":"d".repeat(40),"dirty_input_sha256":"e".repeat(64)},
            "inventory":{"artifact_sha256":"f".repeat(64),"state_sha256":"a".repeat(64),"findings_sha256":"b".repeat(64)},
            "sources":[{"source_id":"attestation","kind":"completeness_attestation","sha256":"c".repeat(64),"byte_length":1,
                "private_reference":"retained source","provenance_reference":"operator review","environment_ids":[ENVIRONMENT],
                "coverage_start_reference":"namespace creation","coverage_end_reference":"stopped cutover"}],
            "owners":[],"reservations":[],"invalid_history":[],"resolutions":[],
            "completeness":{"assertion":"complete-history-for-this-namespace","namespace_start_reference":"creation",
                "coverage_end_reference":"cutover","complete_valid_subject_history":true,"complete_owner_uuid_history":true,
                "owner_uuid_environment_bindings_complete":true,"sources_exhaustive":true,"unresolved_findings":0,
                "asserted_by":"operator","authority_reference":"review","attestation_source":"attestation"},
            "maintenance_reference":"cutover review"})
    }
    fn parse(value: &Value) -> Result<Manifest> {
        parse_manifest(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn empty_union_requires_complete_explicit_attestation() {
        assert!(parse(&manifest()).is_ok());
        let mut value = manifest();
        value["sources"] = json!([]);
        assert!(parse(&value).is_err());
        let mut value = manifest();
        value["completeness"]["sources_exhaustive"] = json!(false);
        assert!(parse(&value).is_err());
        let mut value = manifest();
        value["completeness"]["unresolved_findings"] = json!(1);
        assert!(parse(&value).is_err());
    }

    #[test]
    fn missing_nullable_unknown_fields_and_noncanonical_domains_refuse() {
        let mut value = manifest();
        value["target"]
            .as_object_mut()
            .unwrap()
            .remove("source_commit");
        assert!(parse(&value).is_err());
        let mut value = manifest();
        value["completeness"]["waive_conflicts"] = json!(true);
        assert!(parse(&value).is_err());
        let mut value = manifest();
        value["receipt_id"] = json!("AAAAAAAA-0000-0000-0000-000000000001");
        assert!(parse(&value).is_err());
        let mut value = manifest();
        value["target"]["tool_sha256"] = json!("A".repeat(64));
        assert!(parse(&value).is_err());
        let mut value = manifest();
        value["target"]["dirty_input_sha256"] = Value::Null;
        assert!(parse(&value).is_err());
    }

    #[test]
    fn source_coverage_and_exact_subject_union_are_enforced() {
        let mut value = manifest();
        value["owners"] =
            json!([{"owner_id":OWNER,"environment_id":ENVIRONMENT,"source_refs":["attestation"]}]);
        value["reservations"] =
            json!([{"subject":"\u{1}\t ","owner_id":OWNER,"source_refs":["attestation"]}]);
        assert!(parse(&value).is_ok());
        value["reservations"][0]["subject"] = json!("é");
        assert!(parse(&value).is_err());
        value["reservations"][0]["subject"] = json!("valid");
        value["sources"][0]["environment_ids"] = json!(["30000000-0000-0000-0000-000000000002"]);
        assert!(parse(&value).is_err());
    }

    #[test]
    fn self_attestation_cannot_resolve_unknown_ownership() {
        let mut value = manifest();
        value["resolutions"] = json!([{"finding_id":"a".repeat(64),"kind":"no_ownership_effect","source_refs":["attestation"],"review_reference":"review"}]);
        assert!(parse(&value).is_err());
    }

    fn empty_inventory(m: &mut Manifest) -> Inventory {
        let mut state = HashChain::new("state");
        let collections: Vec<_> = COLLECTIONS
            .iter()
            .map(|name| {
                let collection = Collection {
                    name: (*name).into(),
                    count: 0,
                    sha256: hex_digest(&HashChain::new(name).finish().1),
                };
                state
                    .push(
                        name,
                        metadata_text(&serde_json::to_value(&collection).unwrap()).as_bytes(),
                    )
                    .unwrap();
                collection
            })
            .collect();
        m.target.catalog_sha256 = collections.last().unwrap().sha256.clone();
        m.inventory.state_sha256 = hex_digest(&state.finish().1);
        m.inventory.findings_sha256 = hex_digest(&HashChain::new("findings").finish().1);
        Inventory {
            format: "aegaeon-subject-ownership-inventory".into(),
            version: 1,
            namespace: m.namespace.clone(),
            target: m.target.clone(),
            collections,
            state_sha256: m.inventory.state_sha256.clone(),
            facts: vec![],
            findings: vec![],
            findings_sha256: m.inventory.findings_sha256.clone(),
        }
    }

    #[test]
    fn known_deleted_owner_cannot_be_omitted_or_relocated() {
        let mut m = parse(&manifest()).unwrap();
        let mut inventory = empty_inventory(&mut m);
        assert!(validate_union(&m, &inventory, &m.inventory.artifact_sha256).is_ok());
        inventory.facts.push(Fact {
            fact_id: "a".repeat(64),
            origin: FactOrigin::PermanentOwner,
            row_key: OWNER.into(),
            row_sha256: "b".repeat(64),
            environment_id: ENVIRONMENT.into(),
            owner_id: OWNER.into(),
            subject: None,
            valid: false,
        });
        assert!(validate_union(&m, &inventory, &m.inventory.artifact_sha256).is_err());
        m.owners.push(Owner {
            owner_id: OWNER.into(),
            environment_id: ENVIRONMENT.into(),
            source_refs: vec!["attestation".into()],
        });
        assert!(validate_union(&m, &inventory, &m.inventory.artifact_sha256).is_ok());
        inventory.facts[0].environment_id = "30000000-0000-0000-0000-000000000002".into();
        assert!(validate_union(&m, &inventory, &m.inventory.artifact_sha256).is_err());
    }

    #[test]
    fn inventory_metadata_digest_tampering_refuses() {
        let mut m = parse(&manifest()).unwrap();
        let mut inventory = empty_inventory(&mut m);
        assert!(parse_inventory(&serde_json::to_vec(&inventory).unwrap()).is_ok());
        inventory.collections[0].count = 1;
        assert!(parse_inventory(&serde_json::to_vec(&inventory).unwrap()).is_err());
    }
    const OTHER_ENVIRONMENT: &str = "30000000-0000-0000-0000-000000000002";

    fn reconstruction_manifest() -> Manifest {
        let mut value = manifest();
        let mut evidence = value["sources"][0].clone();
        evidence["source_id"] = json!("external");
        evidence["kind"] = json!("reconstruction");
        evidence["environment_ids"] = json!([ENVIRONMENT, OTHER_ENVIRONMENT]);
        value["sources"].as_array_mut().unwrap().push(evidence);
        value["owners"] =
            json!([{"owner_id":OWNER,"environment_id":ENVIRONMENT,"source_refs":["external"]}]);
        parse(&value).unwrap()
    }

    // Exercise the public parser and union admission with correctly bound IDs and
    // digests. Changing a resolution cannot be hidden by malformed test metadata.
    fn bind_inventory(m: &mut Manifest, inventory: &mut Inventory) {
        for finding in &mut inventory.findings {
            finding.finding_id = content_id(
                "aegaeon-subject-finding-v1",
                &[
                    ("class", Some(&enum_text(&finding.class))),
                    ("origin", Some(&finding.origin)),
                    ("row_key", Some(&finding.row_key)),
                    ("sha256", Some(&finding.row_sha256)),
                ],
            );
        }
        inventory
            .findings
            .sort_by(|a, b| a.finding_id.cmp(&b.finding_id));
        let mut chain = HashChain::new("findings");
        for finding in &inventory.findings {
            chain
                .push(
                    &finding.finding_id,
                    metadata_text(&serde_json::to_value(finding).unwrap()).as_bytes(),
                )
                .unwrap();
        }
        inventory.findings_sha256 = hex_digest(&chain.finish().1);
        m.inventory.findings_sha256 = inventory.findings_sha256.clone();
        let raw = serde_json::to_vec(inventory).unwrap();
        m.inventory.artifact_sha256 = sha256_hex(&raw);
        *inventory = parse_inventory(&raw).unwrap();
    }

    fn observation(class: FindingClass, environment: Option<&str>) -> Finding {
        Finding {
            finding_id: String::new(),
            class,
            origin: "unknown.identity.event".into(),
            row_key: "private-audit-key".into(),
            row_sha256: "a".repeat(64),
            environment_id: environment.map(str::to_owned),
            observed_owner_ids: vec![OWNER.into()],
            observed_subjects: vec![],
            preserved_fact_ids: vec![],
        }
    }

    #[test]
    fn original_outside_class_requires_explicit_claimed_owner_reconstruction() {
        let mut m = reconstruction_manifest();
        let mut inventory = empty_inventory(&mut m);
        inventory.findings.push(observation(
            FindingClass::OutsideTarget,
            Some(OTHER_ENVIRONMENT),
        ));
        bind_inventory(&mut m, &mut inventory);
        assert!(validate_union(&m, &inventory, &m.inventory.artifact_sha256).is_err());
        let finding_id = inventory.findings[0].finding_id.clone();
        m.resolutions.push(Resolution::OutsideTarget {
            finding_id: finding_id.clone(),
            source_refs: vec!["external".into()],
            review_reference: "review".into(),
            environment_id: OTHER_ENVIRONMENT.into(),
        });
        assert!(validate_union(&m, &inventory, &m.inventory.artifact_sha256).is_err());
        m.resolutions[0] = Resolution::ReconstructedOwnership {
            finding_id,
            source_refs: vec!["external".into()],
            review_reference: "review".into(),
            owners: vec![OWNER.into()],
            subjects: vec![],
        };
        validate_union(&m, &inventory, &m.inventory.artifact_sha256).unwrap();
    }

    #[test]
    fn later_outside_resolution_cannot_reclassify_a_claimed_owner() {
        for class in [
            FindingClass::UnscopedEvent,
            FindingClass::UnknownEvent,
            FindingClass::MalformedEvent,
        ] {
            let mut m = reconstruction_manifest();
            let mut inventory = empty_inventory(&mut m);
            inventory.findings.push(observation(class, None));
            bind_inventory(&mut m, &mut inventory);
            let finding_id = inventory.findings[0].finding_id.clone();
            m.resolutions.push(Resolution::OutsideTarget {
                finding_id: finding_id.clone(),
                source_refs: vec!["external".into()],
                review_reference: "review".into(),
                environment_id: OTHER_ENVIRONMENT.into(),
            });
            let error = validate_union(&m, &inventory, &m.inventory.artifact_sha256).unwrap_err();
            assert_eq!(
                error.0,
                "outside classification cannot clear claimed UUID binding"
            );
            m.resolutions[0] = Resolution::ReconstructedOwnership {
                finding_id,
                source_refs: vec!["external".into()],
                review_reference: "review".into(),
                owners: vec![OWNER.into()],
                subjects: vec![],
            };
            validate_union(&m, &inventory, &m.inventory.artifact_sha256).unwrap();
        }
    }

    #[test]
    fn malformed_owner_observation_stays_private_and_requires_invalid_evidence() {
        let mut m = reconstruction_manifest();
        let mut inventory = empty_inventory(&mut m);
        let mut finding = observation(FindingClass::InvalidHistory, Some(ENVIRONMENT));
        finding.origin = "management.user.created.v1".into();
        finding.row_key.push_str(":data.subject");
        finding.observed_owner_ids = vec!["malformed-owner".into(), OWNER.into()];
        finding.observed_subjects = vec!["é".into()];
        inventory.findings.push(finding);
        bind_inventory(&mut m, &mut inventory);
        let finding = &inventory.findings[0];
        assert_eq!(finding.observed_owner_ids[0], "malformed-owner");
        m.resolutions.push(Resolution::ReconstructedOwnership {
            finding_id: finding.finding_id.clone(),
            source_refs: vec!["external".into()],
            review_reference: "review".into(),
            owners: vec![OWNER.into()],
            subjects: vec![],
        });
        assert_eq!(
            validate_union(&m, &inventory, &m.inventory.artifact_sha256)
                .unwrap_err()
                .0,
            "invalid disclosure requires retained evidence"
        );
        let observation_id = content_id(
            "aegaeon-invalid-subject-v1",
            &[
                ("origin", Some(&finding.origin)),
                ("row_key", Some(&finding.row_key)),
                ("sha256", Some(&finding.row_sha256)),
                ("sha256", Some(&sha256_hex(&frame("é".as_bytes())))),
            ],
        );
        let mut evidence = m.sources[1].clone();
        evidence.source_id = "invalid".into();
        evidence.kind = SourceKind::InvalidHistoryEvidence;
        m.sources.push(evidence);
        m.invalid_history.push(InvalidHistory {
            observation_id: observation_id.clone(),
            owner_id: Some(OWNER.into()),
            evidence_source: "invalid".into(),
            source_refs: vec!["external".into(), "invalid".into()],
        });
        m.resolutions[0] = Resolution::InvalidDisclosureRetained {
            finding_id: finding.finding_id.clone(),
            source_refs: vec!["external".into(), "invalid".into()],
            review_reference: "review".into(),
            observation_id,
            owner_id: Some(OWNER.into()),
            evidence_source: "invalid".into(),
        };
        validate_union(&m, &inventory, &m.inventory.artifact_sha256).unwrap();
        if let Resolution::InvalidDisclosureRetained { observation_id, .. } = &mut m.resolutions[0]
        {
            *observation_id = "e".repeat(64);
        }
        assert!(validate_union(&m, &inventory, &m.inventory.artifact_sha256).is_err());
    }
}
