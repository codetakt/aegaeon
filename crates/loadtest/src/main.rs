#![forbid(unsafe_code)]
mod cli;
mod report;
mod runner;
#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(if args.debug {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        })
        .json()
        .init();
    report::execute(args).await
}
