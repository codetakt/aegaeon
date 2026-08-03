#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use tracing::info;

use aegaeon_server::config::DatabaseConfig;
use aegaeon_server::db::{connect_required_pool, preflight_required_schema_revision};
use aegaeon_server::dcr_persistence::preflight_dynamic_registration_schema;
use aegaeon_server::web::management::hosted_bootstrap::{
    bootstrap_hosted_environment, HostedBootstrapInput,
};

fn required_env(key: &'static str) -> Result<String> {
    std::env::var(key)
        .map(|value| value.trim().to_string())
        .with_context(|| format!("{key} is required for hosted bootstrap"))
        .and_then(|value| {
            if value.is_empty() {
                anyhow::bail!("{key} must not be empty");
            }
            Ok(value)
        })
}

fn env_or(key: &'static str, default: &'static str) -> String {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_or_required_env(key: &'static str, fallback_key: &'static str) -> Result<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map_or_else(|| required_env(fallback_key), Ok)
}

fn bootstrap_input_from_env() -> Result<HostedBootstrapInput> {
    Ok(HostedBootstrapInput {
        issuer_url: required_env("AEGAEON_HOSTED_BOOTSTRAP_ISSUER_URL")?,
        owner_email: required_env("AEGAEON_HOSTED_BOOTSTRAP_OWNER_EMAIL")?,
        owner_password: required_env("AEGAEON_HOSTED_BOOTSTRAP_OWNER_PASSWORD")?,
        team_name: env_or("AEGAEON_HOSTED_BOOTSTRAP_TEAM_NAME", "Aegaeon Hosted"),
        team_slug: env_or("AEGAEON_HOSTED_BOOTSTRAP_TEAM_SLUG", "aegaeon-hosted"),
        tenant_name: env_or("AEGAEON_HOSTED_BOOTSTRAP_TENANT_NAME", "Primary Tenant"),
        tenant_slug: env_or("AEGAEON_HOSTED_BOOTSTRAP_TENANT_SLUG", "primary"),
        tenant_region: env_or("AEGAEON_HOSTED_BOOTSTRAP_TENANT_REGION", "aws"),
        environment_name: env_or("AEGAEON_HOSTED_BOOTSTRAP_ENVIRONMENT_NAME", "Hosted Issuer"),
        environment_slug: env_or("AEGAEON_HOSTED_BOOTSTRAP_ENVIRONMENT_SLUG", "issuer"),
        kms_region: env_or_required_env("AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION", "AWS_REGION")?,
        kms_key_id: required_env("AEGAEON_HOSTED_BOOTSTRAP_KMS_KEY_ID")?,
        kms_kid: required_env("AEGAEON_HOSTED_BOOTSTRAP_KMS_KID")?,
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
    let input = bootstrap_input_from_env()?;
    let database = DatabaseConfig::try_from_env()?;
    let pool = connect_required_pool(&database).await?;
    preflight_required_schema_revision(&pool).await?;
    preflight_dynamic_registration_schema(&pool).await?;
    let output = bootstrap_hosted_environment(&pool, input).await?;
    info!(
        status = ?output.status,
        issuer_host = %output.issuer_host,
        team_id = %output.team_id,
        tenant_id = %output.tenant_id,
        environment_id = %output.environment_id,
        configuration_version_id = %output.configuration_version_id,
        runtime_key_id = %output.runtime_key_id,
        "hosted bootstrap completed"
    );
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
