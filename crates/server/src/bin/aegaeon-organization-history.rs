#[tokio::main]
async fn main() -> std::process::ExitCode {
    aegaeon_server::organizations::witness::history::cli::run().await
}
