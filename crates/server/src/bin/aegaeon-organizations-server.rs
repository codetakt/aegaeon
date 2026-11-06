//! Immutable entry for deployments that require independent Organizations authority.
#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    aegaeon_server::server_runtime::run_organizations().await
}
