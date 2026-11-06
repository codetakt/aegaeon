//! Private diagnostic observations, never a supplier qualification receipt.
use super::{Postgres, Redis, DEADLINE};
use clap::{Parser, ValueEnum};
use sqlx::Connection;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

#[derive(Clone, Copy, ValueEnum)]
enum Store {
    Postgres,
    Redis,
    Runtime,
    Credentials,
    History,
}

#[derive(Parser)]
#[command(
    name = "aegaeon-organization-store-inspect",
    about = "Observe actual store identity; never qualify or activate authority"
)]
struct Command {
    #[arg(value_enum)]
    store: Store,
    #[arg(long)]
    root_cert: PathBuf,
    #[arg(long, required_if_eq_any([("store", "runtime"), ("store", "credentials"), ("store", "history")]))]
    environment_id: Option<uuid::Uuid>,
    #[arg(long, required_if_eq_any([("store", "runtime"), ("store", "credentials"), ("store", "history")]))]
    issuer: Option<String>,
    #[arg(long, required_if_eq("store", "history"))]
    deployment_id: Option<uuid::Uuid>,
    #[arg(long, required_if_eq("store", "history"))]
    operation_id: Option<uuid::Uuid>,
    #[arg(long, required_if_eq("store", "history"))]
    expected_revision: Option<i64>,
    #[arg(long, required_if_eq("store", "history"))]
    parent_operation_id: Option<uuid::Uuid>,
    #[arg(long, required_if_eq("store", "history"))]
    parent_expected_revision: Option<i64>,
}

pub async fn run() -> ExitCode {
    crate::install_rustls_crypto_provider();
    let command = Command::parse();
    match tokio::time::timeout(Duration::from_secs(25), execute(command)).await {
        Ok(Ok(())) => ExitCode::SUCCESS,
        _ => {
            eprintln!("store observation unavailable; no qualification or activation established");
            ExitCode::FAILURE
        }
    }
}

async fn execute(command: Command) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            command.store,
            Store::Runtime | Store::Credentials | Store::History
        ) || (command.environment_id.is_none() && command.issuer.is_none())
    );
    anyhow::ensure!(
        matches!(command.store, Store::History)
            || (command.deployment_id.is_none()
                && command.operation_id.is_none()
                && command.expected_revision.is_none()
                && command.parent_operation_id.is_none()
                && command.parent_expected_revision.is_none()),
        "unrelated history selectors"
    );
    let (kind, observed) = match command.store {
        Store::Postgres => (
            "postgres",
            postgres(
                &command.root_cert,
                super::transport::certificate(&command.root_cert)?,
            )
            .await?,
        ),
        Store::Redis => (
            "redis",
            redis(super::transport::certificate(&command.root_cert)?).await?,
        ),
        Store::Runtime => (
            "runtime",
            runtime(
                &command.root_cert,
                command
                    .environment_id
                    .ok_or_else(|| anyhow::anyhow!("Environment absent"))?,
                command
                    .issuer
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("issuer absent"))?,
            )
            .await?,
        ),
        Store::Credentials => (
            "credentials",
            super::credentials::inspect(
                &command.root_cert,
                command
                    .environment_id
                    .ok_or_else(|| anyhow::anyhow!("Environment absent"))?,
                command
                    .issuer
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("issuer absent"))?,
            )
            .await?,
        ),
        Store::History => ("history", history(&command).await?),
    };
    let receipt = serde_json::json!({"version":1,"kind":kind,"observation":observed,
        "activationAuthorized":false,"nonrollbackQualified":false});
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &receipt)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

async fn history(command: &Command) -> anyhow::Result<serde_json::Value> {
    use crate::organizations::witness::{history::audit, Scope};
    let required = || anyhow::anyhow!("explicit history selection required");
    let fence = audit::Fence {
        scope: Scope {
            environment_id: command.environment_id.ok_or_else(required)?,
            deployment_id: command.deployment_id.ok_or_else(required)?,
        },
        operation: command.operation_id.ok_or_else(required)?,
        revision: command.expected_revision.ok_or_else(required)?,
        parent_operation: command.parent_operation_id.ok_or_else(required)?,
        parent_revision: command.parent_expected_revision.ok_or_else(required)?,
    };
    audit::inspect(
        &command.root_cert,
        command.issuer.as_deref().ok_or_else(required)?,
        fence,
    )
    .await
}

async fn postgres(path: &Path, ca: Vec<u8>) -> anyhow::Result<serde_json::Value> {
    anyhow::ensure!(!std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("PG")));
    let endpoint = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL")?;
    let options = super::transport::postgres_options(&endpoint, path, ca)?
        .application_name("aegaeon-organization-store-inspect");
    let connection =
        tokio::time::timeout(DEADLINE, sqlx::PgConnection::connect_with(&options)).await??;
    let link = Postgres::observe(connection).await?;
    let observed = serde_json::to_value(link.observation())?;
    link.close().await?;
    Ok(observed)
}

async fn redis(ca: Vec<u8>) -> anyhow::Result<serde_json::Value> {
    let endpoint = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_REDIS_URL")?;
    let client = super::transport::redis_client(&endpoint, ca)?;
    let config = ::redis::AsyncConnectionConfig::new()
        .set_connection_timeout(DEADLINE)
        .set_response_timeout(DEADLINE);
    let connection = tokio::time::timeout(
        DEADLINE,
        client.get_multiplexed_async_connection_with_config(&config),
    )
    .await??;
    let link = Redis::observe(connection).await?;
    let observed = serde_json::to_value(link.observation())?;
    link.close();
    Ok(observed)
}

async fn runtime(
    ca: &Path,
    environment_id: uuid::Uuid,
    issuer: &str,
) -> anyhow::Result<serde_json::Value> {
    use crate::organizations::witness::connector::{Connector, Endpoint, Primary};
    let control = std::env::var("AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL")?;
    let primary = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL")?;
    let token = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_REDIS_URL")?;
    let connector = Connector::new(
        Endpoint {
            url: &control,
            root_cert: ca,
        },
        Primary {
            endpoint: Endpoint {
                url: &primary,
                root_cert: ca,
            },
            environment_id,
            issuer,
        },
        Endpoint {
            url: &token,
            root_cert: ca,
        },
    )?;
    Ok(connector.connect().await?.inspect().await?)
}

#[cfg(test)]
mod tests {
    use super::super::transport::redis_url;
    #[test]
    fn store_observation_cli_redis_requires_explicit_verified_destination() {
        assert!(redis_url("rediss://observer:fixture@redis.example/3").is_ok());
        for endpoint in [
            "redis://observer:fixture@127.0.0.1/0",
            "rediss://redis.example/0",
            "rediss://observer@redis.example/0",
            "rediss://observer:fixture@redis.example/",
            "rediss://observer:fixture@redis.example/-1",
            "rediss://observer:fixture@redis.example//0",
            "rediss://observer:fixture@redis.example/0#insecure",
            "rediss://observer:fixture@redis.example/0?protocol=resp3",
        ] {
            assert!(redis_url(endpoint).is_err(), "{endpoint}");
        }
    }
}
