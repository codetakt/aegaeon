#![forbid(unsafe_code)]
use aegaeon_server::web::{AppState, OrganizationDeliveryRequest};
use std::io::Read;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = run().await;
    match result {
        Ok(value) => {
            println!("{value}");
            std::process::ExitCode::SUCCESS
        }
        Err(()) => {
            eprintln!("organization delivery unavailable");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<String, ()> {
    aegaeon_server::install_rustls_crypto_provider();
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(4097)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.len() > 4096 {
        return Err(());
    }
    let input: OrganizationDeliveryRequest = serde_json::from_slice(&input).map_err(|_| ())?;
    let state = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        AppState::from_environment(),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let result = state
        .deliver_organization_invitation(input)
        .await
        .map_err(|_| ())?;
    serde_json::to_string(&result).map_err(|_| ())
}
