//! Explicit history provisioning for the freshly created, empty HTTP fixture.
//! This synthetic source attestation does not qualify production completeness.
use super::*;
use crate::organizations::witness::history::Plan;
use crate::subject_ownership::history as source;

pub(super) async fn enroll_empty(
    control: &mut DeploymentControl,
    scope: Scope,
    operation: Uuid,
    initialized: &InitializationOutput,
) -> Result<String> {
    // The owning Python provisioner checks all three empty tables with its
    // fixture-only administrator before setting the enrollment flag. The normal
    // runtime role deliberately cannot read permanent ownership tables directly.
    let mut value = source::test_manifest();
    value["namespace"]["environment_id"] = json!(scope.environment_id);
    value["namespace"]["issuer_host"] = json!(initialized.issuer_host);
    value["sources"][0]["environment_ids"] = json!([scope.environment_id]);
    let mut manifest = source::parse_manifest(&serde_json::to_vec(&value)?)?;
    let inventory = serde_json::to_vec(&source::test_inventory(&mut manifest))?;
    manifest.inventory.artifact_sha256 = source::sha256_hex(&inventory);
    let manifest = serde_json::to_vec(&manifest)?;
    let plan = Plan::from_artifacts(
        &manifest,
        &inventory,
        &source::sha256_hex(&manifest),
        &source::sha256_hex(&inventory),
    )?;
    let maintenance = control.environment_maintenance()?;
    maintenance
        .history_begin(scope, operation, 1, &plan)
        .await?;
    maintenance.history_seal(scope, operation, 1).await?;
    Ok(plan.digest())
}
