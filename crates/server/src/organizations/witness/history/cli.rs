//! Bounded maintenance import/inspection; neither command activates authority.
use super::{hex, initial_digest, Plan, Progress, BATCH_ENTRIES};
use crate::organizations::{
    snapshot::custody::{self, Artifacts},
    witness::{maintenance, Control, Scope},
};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{io::Write, path::PathBuf, process::ExitCode, time::Duration};
use uuid::Uuid;

mod input;
mod inspect;

#[derive(Parser)]
#[command(
    name = "aegaeon-organization-history",
    about = "Retain or inspect independent permanent subject history; never activate authority"
)]
struct Command {
    #[arg(long)]
    environment_id: Uuid,
    #[arg(long)]
    deployment_id: Uuid,
    #[arg(long)]
    operation_id: Uuid,
    #[arg(long)]
    expected_revision: i64,
    /// Exact parent fence; distinct from the Environment fence above.
    #[arg(long)]
    parent_operation_id: Uuid,
    #[arg(long)]
    parent_expected_revision: i64,
    /// New invocation identity; uncertain work requires explicit reconciliation.
    #[arg(long)]
    maintenance_work_id: Uuid,
    #[arg(long)]
    root_cert: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    tool_source_record: PathBuf,
    #[arg(long)]
    dirty_input_record: Option<PathBuf>,
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    Import {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        expected_manifest_sha256: String,
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        expected_inventory_sha256: String,
        /// Explicit source-id=local-path; manifest references are never opened.
        #[arg(long = "source")]
        sources: Vec<String>,
    },
    Inspect,
    /// Restore missing permanent facts to the explicit primary maintenance endpoint.
    Restore {
        #[arg(long)]
        target_runtime_role: String,
        #[arg(long)]
        restoration_operation_id: Uuid,
    },
}

pub async fn run() -> ExitCode {
    let command = Command::parse();
    let output = match Artifacts::create(&command.output_dir) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(3600), execute(&command, &output)).await;
    if matches!(result, Ok(Ok(()))) {
        return ExitCode::SUCCESS;
    }
    // A missing acknowledgement may follow a committed batch/seal. Do not
    // disclose driver credentials, subjects, source references or SQL arguments.
    let failure = json!({"status":"unconfirmed","activationAuthorized":false});
    let _ = output.write("failure.json", failure.to_string().as_bytes());
    eprintln!("history operation unconfirmed; retain the same operation and inputs and reconcile current state");
    ExitCode::FAILURE
}

async fn execute(command: &Command, output: &Artifacts) -> anyhow::Result<()> {
    anyhow::ensure!(
        !command.environment_id.is_nil()
            && !command.deployment_id.is_nil()
            && !command.operation_id.is_nil()
            && command.expected_revision > 0
            && !command.parent_operation_id.is_nil()
            && command.parent_expected_revision > 0
            && !command.maintenance_work_id.is_nil(),
        "explicit fence required"
    );
    let source = custody::identity::tool_source(
        &command.tool_source_record,
        command.dirty_input_record.as_deref(),
        output,
    )
    .map_err(anyhow::Error::msg)?;
    let mut input = input::retain(command, output)?;
    if let Some(input) = input.as_mut() {
        input.recheck(output)?;
    }
    let mut journal = output.history_journal()?;
    // Source custody and all syntax checks precede the first control connection.
    let endpoint = std::env::var("AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL")?;
    let scope = Scope {
        environment_id: command.environment_id,
        deployment_id: command.deployment_id,
    };
    let (kind, plan) = operation_plan(command, &source, input.as_ref().map(|i| &i.plan), scope);
    let mut owner = maintenance::Session::begin(
        &endpoint,
        &command.root_cert,
        maintenance::Request {
            scope,
            parent_operation: command.parent_operation_id,
            parent_revision: command.parent_expected_revision,
            work_id: command.maintenance_work_id,
            kind,
            plan: &plan,
        },
        output,
    )
    .await?;
    let (progress, journal_hash, restoration) = inspect_or_restore(
        command,
        scope,
        input.as_ref().map(|i| &i.plan),
        &mut owner,
        &mut journal,
    )
    .await?;
    if let Some(input) = input.as_mut() {
        input.recheck(output)?;
    }
    let status = if matches!(command.action, Action::Import { .. }) {
        "history-imported"
    } else if matches!(command.action, Action::Restore { .. }) {
        "history-restoration-prepared"
    } else {
        "history-inspected"
    };
    let mut receipt = json!({"version":1,"kind":status,"toolSource":source,"deploymentId":command.deployment_id,
        "inspectionOperationId":command.operation_id,"inspectionRevision":command.expected_revision,
        "history":progress,"journalSha256":journal_hash,"activationAuthorized":false});
    if let Some(restoration) = restoration {
        receipt["restoration"] = serde_json::to_value(restoration)?;
    }
    let receipt = serde_json::to_vec(&receipt)?;
    output.complete_history(&mut journal, &journal_hash, &receipt)?;
    drop(journal);
    owner.finish(output, &receipt).await?;
    writeln!(
        std::io::stdout().lock(),
        "{}",
        json!({"status":status,"sealed":progress.sealed,
        "owners":progress.owner_count,"subjects":progress.subject_count,"sequence":progress.sequence,
        "historySha256":progress.digest,"journalSha256":journal_hash,"durablyRetained":true,"activationAuthorized":false})
    )?;
    Ok(())
}

fn operation_plan(
    command: &Command,
    source: &crate::subject_ownership::history::model::ToolSourceIdentity,
    input: Option<&Plan>,
    scope: Scope,
) -> (&'static str, serde_json::Value) {
    let kind = match command.action {
        Action::Import { .. } => "history-import",
        Action::Inspect => "history-inspect",
        Action::Restore { .. } => "history-restore",
    };
    let target = match &command.action {
        Action::Restore {
            target_runtime_role,
            restoration_operation_id,
        } => json!({"runtimeRole":target_runtime_role,"operationId":restoration_operation_id}),
        _ => serde_json::Value::Null,
    };
    let plan = json!({"version":1,"kind":kind,"toolSource":source,
        "environmentId":scope.environment_id,"deploymentId":scope.deployment_id,
        "childFenceOperation":command.operation_id,"childFenceRevision":command.expected_revision,
        "parentFenceOperation":command.parent_operation_id,"parentFenceRevision":command.parent_expected_revision,
        "workId":command.maintenance_work_id,"input":input.map(|i| json!({
            "manifestSha256":i.manifest_sha256,"inventorySha256":i.inventory_sha256,
            "receiptId":i.receipt_id,"historySha256":super::hex(&i.digest),
            "ownerCount":i.owner_count,"entryCount":i.entries.len(),"sources":i.sources
        })),"target":target,
        "deadlineSeconds":3600,"sourceCountMaximum":256,"sourceBytesMaximum":68719476736u64,
        "journalBytesMaximum":custody::history::JOURNAL_BYTES,"batchEntriesMaximum":BATCH_ENTRIES});
    (kind, plan)
}

async fn inspect_or_restore(
    command: &Command,
    scope: Scope,
    input: Option<&Plan>,
    owner: &mut maintenance::Session,
    journal: &mut std::fs::File,
) -> anyhow::Result<(Progress, String, Option<super::restoration::Preparation>)> {
    if let Some(input) = input {
        import(owner.control(), scope, command, input).await?;
    }
    let (progress, journal_hash) =
        inspect::scan(owner.control(), scope, command, Some(journal), input).await?;
    let restoration = match &command.action {
        Action::Restore {
            target_runtime_role,
            restoration_operation_id,
        } => {
            let request = super::restoration::Request {
                fence: crate::organizations::snapshot::staging::recovery::Fence {
                    scope,
                    operation_id: command.operation_id,
                    revision: command.expected_revision,
                },
                operation_id: *restoration_operation_id,
                runtime_role: target_runtime_role,
                expected: &progress,
            };
            Some(owner.restore(request).await?)
        }
        _ => None,
    };
    Ok((progress, journal_hash, restoration))
}

async fn import(
    control: &mut Control,
    scope: Scope,
    command: &Command,
    plan: &Plan,
) -> anyhow::Result<()> {
    let before = control
        .history_begin(scope, command.operation_id, command.expected_revision, plan)
        .await?;
    // Verify the complete retained prefix before resuming at its actual boundary.
    // This also reconciles a batch whose previous acknowledgement was lost.
    let (observed, _) = inspect::scan(control, scope, command, None, Some(plan)).await?;
    anyhow::ensure!(observed == before, "history changed during reconciliation");
    let from = usize::try_from(before.sequence)?;
    anyhow::ensure!(from <= plan.entries.len(), "history exceeds import plan");
    let mut digest = initial_digest(plan.environment_id, &plan.issuer_host)?;
    for (index, entry) in plan.entries[..from].iter().enumerate() {
        digest = entry.extend_digest(digest, index as u64 + 1)?;
    }
    anyhow::ensure!(hex(&digest) == before.digest, "history prefix differs");
    let mut sequence = from as u64;
    for entries in plan.entries[from..].chunks(BATCH_ENTRIES) {
        let after = control
            .history_batch(
                scope,
                command.operation_id,
                command.expected_revision,
                sequence,
                entries,
            )
            .await?;
        for entry in entries {
            sequence += 1;
            digest = entry.extend_digest(digest, sequence)?;
        }
        anyhow::ensure!(
            after.sequence == sequence && after.digest == hex(&digest),
            "batch acknowledgement differs"
        );
    }
    let sealed = control
        .history_seal(scope, command.operation_id, command.expected_revision)
        .await?;
    anyhow::ensure!(
        sealed.digest == plan.digest() && sealed.sequence == plan.entries.len() as u64,
        "sealed history differs"
    );
    Ok(())
}
