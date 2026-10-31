//! Explicit inactive destination preparation; no serving activation capability.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    aegaeon_server::organizations::snapshot::cli::run_prepare().await
}
