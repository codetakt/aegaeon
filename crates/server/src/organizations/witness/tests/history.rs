use super::*;
use crate::organizations::witness::history::{Entry, Plan};
use crate::subject_ownership::history as source;
use serde_json::json;

mod boundaries;
mod concurrency;
mod pages;

fn scope() -> Scope {
    Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    }
}

fn plan(scope: Scope, owners: &[(Uuid, Vec<&str>)]) -> anyhow::Result<Plan> {
    let mut value = source::test_manifest();
    let environment = scope.environment_id.to_string();
    value["namespace"]["environment_id"] = json!(environment);
    value["namespace"]["issuer_host"] = json!(format!("{}.example", scope.environment_id));
    value["sources"][0]["environment_ids"] = json!([environment]);
    value["owners"] = json!(owners.iter().map(|(owner,_)|json!({"owner_id":owner,"environment_id":environment,"source_refs":["attestation"]})).collect::<Vec<_>>());
    value["reservations"] = json!(owners
        .iter()
        .flat_map(|(owner, subjects)| subjects.iter().map(
            move |subject| json!({"owner_id":owner,"subject":subject,"source_refs":["attestation"]})
        ))
        .collect::<Vec<_>>());
    let mut manifest = source::parse_manifest(&serde_json::to_vec(&value)?)?;
    let inventory = serde_json::to_vec(&source::test_inventory(&mut manifest))?;
    manifest.inventory.artifact_sha256 = source::sha256_hex(&inventory);
    let manifest = serde_json::to_vec(&manifest)?;
    Ok(Plan::from_artifacts(
        &manifest,
        &inventory,
        &source::sha256_hex(&manifest),
        &source::sha256_hex(&inventory),
    )?)
}

async fn enrolled(control: &mut Control, scope: Scope, plan: &Plan) -> anyhow::Result<Uuid> {
    let operation = Uuid::new_v4();
    control.initialize(scope, operation).await?;
    control.history_begin(scope, operation, 1, plan).await?;
    let mut offset = 0;
    for entries in plan.batches() {
        let progress = control
            .history_batch(scope, operation, 1, offset, entries)
            .await?;
        offset = progress.sequence;
    }
    control.history_seal(scope, operation, 1).await?;
    Ok(operation)
}

async fn activated(
    control: &mut Control,
    scope: Scope,
    operation: Uuid,
    plan: &Plan,
) -> anyhow::Result<Selection> {
    let selected = Selection {
        history_sha256: plan.digest(),
        ..selection()
    };
    control.prepare(scope, operation, 1, &selected).await?;
    control
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    Ok(selected)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; history import replay, exact IDs and sealing"]
async fn pg_organizations_history_import_replay_and_sealing() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = import(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}
async fn import(f: &mut Fixture) -> TestResult {
    let scope = scope();
    let operation = Uuid::new_v4();
    let plan = plan(
        scope,
        &[
            (Uuid::from_u128(1), vec!["a"]),
            (Uuid::nil(), vec!["\u{1}A", "A"]),
        ],
    )?;
    let entries = plan.batches().flatten().cloned().collect::<Vec<_>>();
    let mut maintenance = f.connect(Role::Maintenance).await?;
    maintenance.initialize(scope, operation).await?;
    anyhow::ensure!(maintenance
        .history_begin(scope, operation, 2, &plan)
        .await
        .is_err());
    let progress = maintenance
        .history_begin(scope, operation, 1, &plan)
        .await?;
    anyhow::ensure!(!progress.sealed && progress.sequence == 0);
    anyhow::ensure!(maintenance.history_seal(scope, operation, 1).await.is_err());
    let first = maintenance
        .history_batch(scope, operation, 1, 0, &entries[..1])
        .await?;
    anyhow::ensure!(first.sequence == 1 && first.owner_count == 1);
    let replay = maintenance
        .history_batch(scope, operation, 1, 0, &entries[..1])
        .await?;
    anyhow::ensure!(replay.digest == first.digest && replay.sequence == 1);
    anyhow::ensure!(
        maintenance
            .history_batch(scope, operation, 1, 0, &entries[..2])
            .await
            .is_err(),
        "partial overlap must refuse"
    );
    anyhow::ensure!(maintenance
        .history_batch(scope, operation, 1, 0, &[Entry::owner(Uuid::new_v4())])
        .await
        .is_err());

    // First entry would be valid, but the last entry duplicates the earlier
    // owner. The entire actual SQL statement must roll back.
    let invalid = [entries[1].clone(), entries[0].clone()];
    anyhow::ensure!(maintenance
        .history_batch(scope, operation, 1, 1, &invalid)
        .await
        .is_err());
    let after = maintenance
        .history_read(scope, operation, 1, 0, 256)
        .await?;
    anyhow::ensure!(after.progress.sequence == 1 && after.entries.len() == 1);
    let final_batch = maintenance
        .history_batch(scope, operation, 1, 1, &entries[1..])
        .await?;
    anyhow::ensure!(final_batch.digest == plan.digest() && final_batch.sequence == 5);
    let sealed = maintenance.history_seal(scope, operation, 1).await?;
    anyhow::ensure!(sealed.sealed && sealed.digest == plan.digest());
    anyhow::ensure!(maintenance.history_seal(scope, operation, 1).await?.sealed);
    anyhow::ensure!(
        maintenance
            .history_batch(scope, operation, 1, 0, &entries)
            .await?
            .sequence
            == 5
    );
    let page = maintenance.history_read(scope, operation, 1, 1, 2).await?;
    anyhow::ensure!(page.entries.len() == 2 && page.entries[0].owner_id == Uuid::from_u128(1));
    anyhow::ensure!(page.entries[1].subject.as_deref() == Some("\u{1}A"));
    anyhow::ensure!(page
        .entries
        .iter()
        .all(|entry| entry.principal == f.maintenance
            && entry.operation_id == operation
            && entry.epoch.is_none()));
    anyhow::ensure!(maintenance
        .history_batch(scope, operation, 1, 5, &[Entry::owner(Uuid::new_v4())])
        .await
        .is_err());
    maintenance.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; retained owners, exact subjects and retired admission"]
async fn pg_organizations_history_runtime_preserves_ownership() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = runtime(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}
async fn runtime(f: &mut Fixture) -> TestResult {
    let first = scope();
    let second = scope();
    let owner = Uuid::nil();
    let other = Uuid::new_v4();
    let initial = plan(first, &[(owner, vec!["A"])])?;
    let empty = plan(second, &[])?;
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let op = enrolled(&mut maintenance, first, &initial).await?;
    let second_op = enrolled(&mut maintenance, second, &empty).await?;
    let selection = activated(&mut maintenance, first, op, &initial).await?;
    let second_selection = activated(&mut maintenance, second, second_op, &empty).await?;
    let mut runtime = f.connect(Role::Runtime).await?;
    let admission = runtime.acquire(first, &selection, Uuid::new_v4()).await?;
    let second_admission = runtime
        .acquire(second, &second_selection, Uuid::new_v4())
        .await?;
    anyhow::ensure!(
        runtime
            .history_check(&admission, owner, "A")
            .await?
            .sequence
            == 2
    );
    anyhow::ensure!(
        runtime
            .history_reserve(&admission, owner, "A")
            .await?
            .sequence
            == 2
    );
    anyhow::ensure!(
        runtime
            .history_reserve(&admission, owner, "a")
            .await?
            .sequence
            == 3
    );
    anyhow::ensure!(runtime
        .history_reserve(&admission, other, "A")
        .await
        .is_err());
    anyhow::ensure!(
        runtime
            .history_check(&admission, owner, "a")
            .await?
            .sequence
            == 3,
        "conflicting owner append must roll back"
    );
    anyhow::ensure!(
        runtime
            .history_reserve(&second_admission, owner, "A")
            .await
            .is_err(),
        "global owner cannot move Environment"
    );
    anyhow::ensure!(
        runtime
            .history_reserve(&second_admission, other, "A")
            .await?
            .sequence
            == 2,
        "same subject may belong to another scoped owner"
    );
    anyhow::ensure!(runtime.history_check(&admission, other, "A").await.is_err());
    runtime.complete(&admission).await?;
    anyhow::ensure!(runtime.history_check(&admission, owner, "A").await.is_err());
    let reused = runtime.acquire(first, &selection, Uuid::new_v4()).await?;
    anyhow::ensure!(runtime
        .history_reserve(&admission, owner, "stale")
        .await
        .is_err());
    let fence = maintenance.fence(first, Uuid::new_v4(), 3).await?;
    anyhow::ensure!(fence.pending == 1);
    anyhow::ensure!(runtime.history_check(&reused, owner, "A").await.is_err());
    runtime.complete(&reused).await?;
    let page = maintenance
        .history_read(first, fence.operation_id, fence.revision, 0, 256)
        .await?;
    anyhow::ensure!(page.progress.sequence == 3 && page.entries.len() == 3);
    let event = &page.entries[2];
    anyhow::ensure!(
        event.principal == f.runtime
            && event.operation_id == op
            && event.epoch == Some(selection.epoch)
            && event.worker_id == Some(admission.slot.worker_id)
            && event.slot == Some(admission.slot.slot)
            && event.generation == Some(admission.slot.generation)
    );
    runtime.complete(&second_admission).await?;
    runtime.close().await?;
    maintenance.close().await?;
    Ok(())
}
