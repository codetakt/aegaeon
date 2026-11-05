//! Observe or fence the separate control store. No activation command exists.
use super::{
    deployment::{DeploymentControl, DeploymentId},
    Control, Role, Scope,
};
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
    environment_id: Option<Uuid>,
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
    /// Operate on the deployment parent, without an Environment selector.
    Deployment {
        #[command(subcommand)]
        action: DeploymentAction,
    },
    Status,
    Pending,
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

#[derive(Subcommand)]
enum DeploymentAction {
    Status,
    Pending,
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

impl Command {
    fn scope(&self) -> anyhow::Result<Option<Scope>> {
        anyhow::ensure!(!self.deployment_id.is_nil(), "deployment identity required");
        if matches!(&self.action, Action::Deployment { .. }) {
            anyhow::ensure!(
                self.environment_id.is_none(),
                "deployment action has no Environment"
            );
            Ok(None)
        } else {
            let environment_id = self
                .environment_id
                .filter(|id| !id.is_nil())
                .ok_or_else(|| anyhow::anyhow!("Environment identity required"))?;
            Ok(Some(Scope {
                environment_id,
                deployment_id: self.deployment_id,
            }))
        }
    }
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
    let scope = command.scope()?;
    let deployment = DeploymentId::new(command.deployment_id)?;
    let endpoint = std::env::var("AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL")?;
    let role = match command.role {
        Login::Runtime => Role::Runtime,
        Login::Maintenance => Role::Maintenance,
    };
    let mut control = DeploymentControl::connect(&endpoint, &command.root_cert, role).await?;
    let state = match (command.action, scope) {
        (Action::Deployment { action }, None) => {
            deployment_action(&mut control, deployment, action).await
        }
        (action, Some(scope)) => {
            environment_action(control.environment_control(), scope, action).await
        }
        _ => Err(anyhow::anyhow!("control scope differs")),
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

async fn environment_action(
    control: &mut Control,
    scope: Scope,
    action: Action,
) -> anyhow::Result<serde_json::Value> {
    let result = match action {
        Action::Status => serde_json::to_value(control.current(scope).await?),
        Action::Pending => serde_json::to_value(control.pending(scope).await?),
        Action::Initialize { operation_id } => {
            anyhow::ensure!(!operation_id.is_nil(), "operation identity required");
            serde_json::to_value(control.initialize(scope, operation_id).await?)
        }
        Action::Fence {
            operation_id,
            expected_revision,
        } => {
            anyhow::ensure!(
                !operation_id.is_nil() && expected_revision > 0,
                "exact fence required"
            );
            serde_json::to_value(
                control
                    .fence(scope, operation_id, expected_revision)
                    .await?,
            )
        }
        Action::Deployment { .. } => anyhow::bail!("Environment action required"),
    };
    result.map_err(anyhow::Error::from)
}

async fn deployment_action(
    control: &mut DeploymentControl,
    deployment: DeploymentId,
    action: DeploymentAction,
) -> anyhow::Result<serde_json::Value> {
    let state = match action {
        DeploymentAction::Status => serde_json::to_value(control.current(deployment).await?),
        DeploymentAction::Pending => serde_json::to_value(control.pending(deployment).await?),
        DeploymentAction::Initialize { operation_id } => {
            anyhow::ensure!(!operation_id.is_nil(), "operation identity required");
            serde_json::to_value(control.initialize(deployment, operation_id).await?)
        }
        DeploymentAction::Fence {
            operation_id,
            expected_revision,
        } => {
            anyhow::ensure!(
                !operation_id.is_nil() && expected_revision > 0,
                "exact fence required"
            );
            serde_json::to_value(
                control
                    .fence(deployment, operation_id, expected_revision)
                    .await?,
            )
        }
    };
    state.map_err(anyhow::Error::from)
}
