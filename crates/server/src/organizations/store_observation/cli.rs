//! Private diagnostic observations, never a supplier qualification receipt.
use super::{Postgres, Redis, DEADLINE};
use clap::{Parser, ValueEnum};
use sqlx::Connection;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

#[derive(Clone, Copy, ValueEnum)]
enum Store {
    Postgres,
    Redis,
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
    let ca = certificate(&command.root_cert)?;
    let (kind, observed) = match command.store {
        Store::Postgres => ("postgres", postgres(&command.root_cert, ca).await?),
        Store::Redis => ("redis", redis(ca).await?),
    };
    let receipt = serde_json::json!({"version":1,"kind":kind,"observation":observed,
        "activationAuthorized":false,"nonrollbackQualified":false});
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &receipt)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    anyhow::ensure!(file.metadata()?.is_file());
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes)?;
    anyhow::ensure!(!bytes.is_empty() && bytes.len() <= 1_048_576);
    Ok(bytes)
}

async fn postgres(path: &Path, ca: Vec<u8>) -> anyhow::Result<serde_json::Value> {
    anyhow::ensure!(!std::env::vars_os().any(|(key, _)| key.to_string_lossy().starts_with("PG")));
    let endpoint = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL")?;
    let options = crate::organizations::witness::connection::options(&endpoint, path)?
        .ssl_root_cert_from_pem(ca)
        .application_name("aegaeon-organization-store-inspect");
    let connection =
        tokio::time::timeout(DEADLINE, sqlx::PgConnection::connect_with(&options)).await??;
    let link = Postgres::observe(connection).await?;
    let observed = serde_json::to_value(link.observation())?;
    link.close().await?;
    Ok(observed)
}

fn redis_url(endpoint: &str) -> anyhow::Result<url::Url> {
    anyhow::ensure!(endpoint.len() <= 16_384);
    let url = url::Url::parse(endpoint)?;
    anyhow::ensure!(
        url.scheme() == "rediss"
            && url.host_str().is_some_and(|host| !host.is_empty())
            && !url.username().is_empty()
            && url.password().is_some_and(|password| !password.is_empty())
            && url.query().is_none()
            && url.fragment().is_none()
    );
    let database = url
        .path()
        .strip_prefix('/')
        .ok_or_else(|| anyhow::anyhow!("database absent"))?;
    anyhow::ensure!(!database.is_empty() && database.bytes().all(|b| b.is_ascii_digit()));
    let _: u32 = database.parse()?;
    Ok(url)
}

async fn redis(ca: Vec<u8>) -> anyhow::Result<serde_json::Value> {
    let endpoint = std::env::var("AEGAEON_ORGANIZATION_OBSERVATION_REDIS_URL")?;
    let url = redis_url(&endpoint)?;
    let client = ::redis::Client::build_with_tls(
        url,
        ::redis::TlsCertificates {
            client_tls: None,
            root_cert: Some(ca),
        },
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;
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
