//! Observe or fence the separate control store. No activation command exists.
use super::{Control, Role, Scope};
use clap::{Parser, Subcommand, ValueEnum};
use std::{io::Write, path::PathBuf, process::ExitCode, time::Duration};
use uuid::Uuid;

#[derive(Clone, Copy, ValueEnum)]
enum Login {
    Runtime,
    Maintenance,
}
#[derive(Parser)]
#[command(
    name = "aegaeon-organization-witness",
    about = "Inspect or fence the independent Organizations control store; never activate authority"
)]
struct Command {
    #[arg(long)]
    environment_id: Uuid,
    #[arg(long)]
    deployment_id: Uuid,
    #[arg(long)]
    role: Login,
    #[arg(long)]
    root_cert: PathBuf,
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    Status,
    Initialize {
        #[arg(long)]
        operation_id: Uuid,
    },
    Fence {
        #[arg(long)]
        operation_id: Uuid,
        #[arg(long)]
        expected_revision: i64,
    },
}

pub async fn run() -> ExitCode {
    let command = Command::parse();
    let result = tokio::time::timeout(Duration::from_secs(25), execute(command)).await;
    match result {
        Ok(Ok(())) => ExitCode::SUCCESS,
        _ => {
            // Never print the URL, SQL arguments or driver credentials. A failed
            // acknowledgement can follow a commit; status/replay is required.
            eprintln!("control-store operation unconfirmed; retain its identity and reconcile current state");
            ExitCode::FAILURE
        }
    }
}
async fn execute(command: Command) -> anyhow::Result<()> {
    let endpoint = std::env::var("AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL")?;
    let role = match command.role {
        Login::Runtime => Role::Runtime,
        Login::Maintenance => Role::Maintenance,
    };
    let mut control = Control::connect(&endpoint, &command.root_cert, role).await?;
    let scope = Scope {
        environment_id: command.environment_id,
        deployment_id: command.deployment_id,
    };
    let state = match command.action {
        Action::Status => control.current(scope).await,
        Action::Initialize { operation_id } => control.initialize(scope, operation_id).await,
        Action::Fence {
            operation_id,
            expected_revision,
        } => control.fence(scope, operation_id, expected_revision).await,
    };
    let close = control.close().await;
    let state = state?;
    close?;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &state)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
