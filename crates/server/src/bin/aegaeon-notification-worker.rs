#![forbid(unsafe_code)]
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Process durable notifications for the configured Environment")]
struct Args {
    /// Private regular file containing the transport credential and key ring.
    #[arg(long)]
    key_file: PathBuf,
    /// Stop when idle or after at most sixteen current message attempts.
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("notification_worker=info")
        .init();
    match aegaeon_server::server_runtime::run_notification_worker(&args.key_file, args.once).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("notification worker unavailable");
            std::process::ExitCode::FAILURE
        }
    }
}
