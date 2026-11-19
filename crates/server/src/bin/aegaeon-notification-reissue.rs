#![forbid(unsafe_code)]
use aegaeon_server::web::NotificationReissueRequest;
use clap::Parser;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(about = "Explicitly reissue one authorized notification without extending its expiry")]
struct Args {
    #[arg(long)]
    key_file: PathBuf,
    #[arg(long)]
    domain_id: Uuid,
    #[arg(long)]
    invitation_id: Uuid,
    #[arg(long, conflicts_with = "identity_request_id")]
    challenge_id: Option<Uuid>,
    #[arg(long)]
    identity_request_id: Option<Uuid>,
    #[arg(long)]
    expected_delivery_revision: i64,
    /// Retain and reuse this UUID when reconciling an uncertain command result.
    #[arg(long)]
    operation_id: Uuid,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let request = NotificationReissueRequest {
        domain_id: args.domain_id,
        invitation_id: args.invitation_id,
        challenge_id: args.challenge_id,
        identity_request_id: args.identity_request_id,
        expected_delivery_revision: args.expected_delivery_revision,
        operation_id: args.operation_id,
    };
    match aegaeon_server::server_runtime::run_notification_reissue(&args.key_file, request).await {
        Ok(value) if serde_json::to_writer(std::io::stdout(), &value).is_ok() => {
            std::process::ExitCode::SUCCESS
        }
        _ => {
            eprintln!("notification reissue unavailable");
            std::process::ExitCode::FAILURE
        }
    }
}
