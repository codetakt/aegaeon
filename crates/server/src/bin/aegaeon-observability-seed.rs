#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use tracing::info;

use aegaeon_server::config::DatabaseConfig;
use aegaeon_server::db::{connect_required_pool, preflight_required_schema_revision};
use aegaeon_server::dcr_persistence::preflight_dynamic_registration_schema;
use aegaeon_server::web::management::hosted_bootstrap::seed_observability_environment;

fn required_env(key: &'static str) -> Result<String> {
    std::env::var(key)
        .map(|value| value.trim().to_string())
        .with_context(|| format!("{key} is required for observability seed"))
        .and_then(|value| {
            if value.is_empty() {
                anyhow::bail!("{key} must not be empty");
            }
            Ok(value)
        })
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    aegaeon_server::install_rustls_crypto_provider();
    init_tracing();
    let issuer_host = required_env("AEGAEON_RUNTIME_ISSUER_HOST")?;
    let api_key = required_env("AEGAEON_OBSERVABILITY_API_KEY")?;
    let database = DatabaseConfig::try_from_env()?;
    let pool = connect_required_pool(&database).await?;
    preflight_required_schema_revision(&pool).await?;
    preflight_dynamic_registration_schema(&pool).await?;
    let output = seed_observability_environment(&pool, &issuer_host, &api_key).await?;
    info!(
        status = ?output.status,
        issuer_host = %output.issuer_host,
        environment_id = %output.environment_id,
        configuration_version_id = %output.configuration_version_id,
        api_key_id = %output.api_key_id,
        "observability runtime configuration seed completed"
    );
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
