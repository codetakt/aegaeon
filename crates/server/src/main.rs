#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    aegaeon_server::server_runtime::run().await
}
