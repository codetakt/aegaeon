//! Actual store diagnostics; no activation or nonrollback qualification.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    aegaeon_server::organizations::store_observation::cli::run().await
}
