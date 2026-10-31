//! Bounded maintenance import/inspection; neither command activates authority.
use super::{hex, initial_digest, Plan, Progress, BATCH_ENTRIES};
use crate::organizations::{
    snapshot::custody::{self, Artifacts},
    witness::{Control, Role, Scope},
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
            && command.expected_revision > 0,
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
    let mut control = Control::connect(&endpoint, &command.root_cert, Role::Maintenance).await?;
    let scope = Scope {
        environment_id: command.environment_id,
        deployment_id: command.deployment_id,
    };
    let result = async {
        if let Some(input) = &input {
            import(&mut control, scope, command, &input.plan).await?;
        }
        inspect::scan(
            &mut control,
            scope,
            command,
            Some(&mut journal),
            input.as_ref().map(|i| &i.plan),
        )
        .await
    }
    .await;
    let close = control.close().await;
    let (progress, journal_hash) = result?;
    close?;
    if let Some(input) = input.as_mut() {
        input.recheck(output)?;
    }
    let status = if matches!(command.action, Action::Import { .. }) {
        "history-imported"
    } else {
        "history-inspected"
    };
    let receipt = json!({"version":1,"kind":status,"toolSource":source,"deploymentId":command.deployment_id,
        "inspectionOperationId":command.operation_id,"inspectionRevision":command.expected_revision,
        "history":progress,"journalSha256":journal_hash,"activationAuthorized":false});
    output.complete_history(&mut journal, &journal_hash, &serde_json::to_vec(&receipt)?)?;
    writeln!(
        std::io::stdout().lock(),
        "{}",
        json!({"status":status,"sealed":progress.sealed,
        "owners":progress.owner_count,"subjects":progress.subject_count,"sequence":progress.sequence,
        "historySha256":progress.digest,"journalSha256":journal_hash,"durablyRetained":true,"activationAuthorized":false})
    )?;
    Ok(())
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
