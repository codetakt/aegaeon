#![forbid(unsafe_code)]

use aegaeon_server::config::DatabaseConfig;
use aegaeon_server::db::{connect_required_pool, preflight_required_schema_revision};
use aegaeon_server::web::management::initialization::{initialize_management, InitializationInput};
use anyhow::{anyhow, bail, Result};
use clap::Parser;
use std::io::Read;

#[derive(Parser)]
#[command(
    about = "Initialize an empty management database from bounded JSON on stdin. See docs/operations/management-initialization.md."
)]
struct Command {}

// Credentials are supplied on stdin, never in process arguments or output.
fn read_input(reader: impl Read) -> Result<InitializationInput> {
    let mut bytes = Vec::new();
    reader
        .take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("cannot read initialization input"))?;
    if bytes.len() > 16_384 {
        bail!("initialization input exceeds 16384 bytes");
    }
    serde_json::from_slice(&bytes).map_err(|_| anyhow!("initialization input must be a strict JSON object with ownerEmail, ownerPassword, allowedOrigins and issuerBaseDomain"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = Command::parse();
    aegaeon_server::install_rustls_crypto_provider();
    let input = read_input(std::io::stdin().lock())?;
    let config = DatabaseConfig::try_from_env()?;
    let pool = connect_required_pool(&config).await?;
    preflight_required_schema_revision(&pool).await?;
    let output = initialize_management(&pool, &input).await?;
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_is_bounded_and_parser_errors_do_not_echo_secrets() {
        for bytes in [
            vec![b'x'; 16_385],
            br#"{"ownerPassword":"secret-marker","unknown":"secret-marker"}"#.to_vec(),
            br#"{"ownerPassword":"secret-marker","ownerPassword":"second"}"#.to_vec(),
        ] {
            let error = read_input(bytes.as_slice())
                .err()
                .expect("input must be rejected");
            assert!(!error.to_string().contains("secret-marker"));
        }
    }
}
