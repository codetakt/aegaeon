//! Independent control-store observation and fencing; no authority activation.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    aegaeon_server::organizations::witness::cli::run().await
}
