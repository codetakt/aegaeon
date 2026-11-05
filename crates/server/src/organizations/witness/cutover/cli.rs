//! Root-custodied input and verified native connections for epoch preparation.
use super::{activation, transaction, Plan};
use crate::organizations::{
    store_observation::{transport, Postgres, Redis},
    witness::{deployment::DeploymentControl, Role},
};
use anyhow::{ensure, Result};
use clap::Parser;
use rustix::fs::{self, Mode, OFlags};
use sqlx::{Connection, PgConnection};
use std::{
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

const MAX_INPUT: u64 = 256 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(
    name = "aegaeon-organization-epoch-prepare",
    about = "Advance registered offline epochs while selected workers stay stopped"
)]
struct Command {
    #[arg(long)]
    intent: PathBuf,
    #[arg(long)]
    root_cert: PathBuf,
    /// Check one complete startup document without connecting or preparing epochs.
    #[arg(long)]
    check_startup: Option<PathBuf>,
    /// Activate the complete prepared inventory under its registered intent.
    #[arg(long, conflicts_with = "check_startup")]
    activate: Option<PathBuf>,
}

pub async fn run() -> ExitCode {
    crate::install_rustls_crypto_provider();
    let command = Command::parse();
    match tokio::time::timeout(Duration::from_secs(50), execute(command)).await {
        Ok(Ok(())) => ExitCode::SUCCESS,
        _ => {
            eprintln!(
                "epoch transition unconfirmed; reconcile the original intent; keep workers stopped"
            );
            ExitCode::FAILURE
        }
    }
}

pub(super) fn private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        rustix::process::geteuid().as_raw() == 0,
        "offline root custody required"
    );
    ensure!(path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir)));
    for parent in path.ancestors().skip(1) {
        let info = std::fs::symlink_metadata(parent)?;
        ensure!(info.is_dir() && info.uid() == 0 && info.mode() & 0o022 == 0);
    }
    let file = std::fs::File::from(fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let info = file.metadata()?;
    ensure!(info.is_file() && info.uid() == 0 && info.mode() & 0o077 == 0 && info.nlink() == 1);
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(!bytes.is_empty() && bytes.len() as u64 <= limit);
    Ok(bytes)
}

async fn execute(command: Command) -> Result<()> {
    let bytes = private(&command.intent, MAX_INPUT)?;
    let plan: Plan = serde_json::from_slice(&bytes)?;
    plan.validate()?;
    let digest = crate::subject_ownership::history::sha256_hex(&bytes);
    let ca = private(&command.root_cert, MAX_INPUT)?;
    ensure!(!std::env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with("PG")));
    if let Some(path) = command.check_startup {
        use crate::organizations::witness::deployment::configuration::{
            Configuration, MAX_CONFIGURATION_BYTES,
        };
        let bytes = private(&path, MAX_CONFIGURATION_BYTES as u64)?;
        let selectors = Configuration::parse(&bytes)?.check_cutover(&plan)?;
        let selectors: Vec<_> = selectors
            .into_iter()
            .map(|(id, host)| serde_json::json!({"environmentId": id, "issuerHost": host}))
            .collect();
        return emit(&serde_json::json!({
            "version":1,"kind":"startup-configuration","intentSha256":digest,
            "configurationSha256":crate::subject_ownership::history::sha256_hex(&bytes),
            "rootCertSha256":crate::subject_ownership::history::sha256_hex(&ca),
            "startupSelectors":selectors,
            "activationAuthorized":false,"supplierQualified":false
        }));
    }
    let control_url = std::env::var("AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL")?;
    let primary_url = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL")?;
    let token_url = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_REDIS_URL")?;
    let activation = if let Some(path) = command.activate {
        let bytes = private(&path, 1024 * 1024)?;
        let intent: activation::Intent = serde_json::from_slice(&bytes)?;
        intent.check(&plan, &digest, &ca, &primary_url, &token_url)?;
        Some((
            intent,
            crate::subject_ownership::history::sha256_hex(&bytes),
        ))
    } else {
        None
    };
    let control_options =
        transport::postgres_options(&control_url, &command.root_cert, ca.clone())?;
    let control = DeploymentControl::checked(
        tokio::time::timeout(DEADLINE, PgConnection::connect_with(&control_options)).await??,
        Role::Maintenance,
    )
    .await?;
    let primary_options =
        transport::postgres_options(&primary_url, &command.root_cert, ca.clone())?;
    let mut primary =
        tokio::time::timeout(DEADLINE, PgConnection::connect_with(&primary_options)).await??;
    for child in &plan.children {
        tokio::time::timeout(
            DEADLINE,
            crate::web::namespace_runtime::validate_connection_inputs(
                &mut primary,
                child.environment_id,
                &child.issuer,
            ),
        )
        .await??;
    }
    let primary = Postgres::observe(primary).await?;
    let token = transport::redis_client(&token_url, ca)?;
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(DEADLINE)
        .set_response_timeout(DEADLINE);
    let token = tokio::time::timeout(
        DEADLINE,
        token.get_multiplexed_async_connection_with_config(&config),
    )
    .await??;
    let token = Redis::observe(token).await?;
    let receipt = if let Some((intent, digest)) = activation {
        activation::activate(control, primary, token, &plan, &intent, &digest).await?
    } else {
        transaction::prepare(control, primary, token, &plan, &digest).await?
    };
    emit(&receipt)
}

fn emit(receipt: &serde_json::Value) -> Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, receipt)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
