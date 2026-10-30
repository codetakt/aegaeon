#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> std::process::ExitCode {
    aegaeon_server::organizations::snapshot::cli::run().await
}
