#![forbid(unsafe_code)]

mod cli;
#[cfg(feature = "openapi")]
mod openapi;
mod tasks;

use std::{env, path::Path, process::ExitCode};

fn main() -> ExitCode {
    let task = match cli::parse(env::args_os().skip(1)) {
        Ok(task) => task,
        Err(error) => {
            eprintln!("{error}\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let result = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve repository root"))
        .and_then(|root| tasks::run(root, task));
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
