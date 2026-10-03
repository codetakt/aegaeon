#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> std::process::ExitCode {
    aegaeon_server::subject_ownership::history::cli::run().await
}
