//! Strict local registration metadata preflight for a quiescent predecessor database.
use std::{io::Write, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        eprintln!("Usage: AEGAEON_DATABASE_URL=... aegaeon-registration-preflight");
        return ExitCode::FAILURE;
    }
    match run().await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<bool, &'static str> {
    let url = std::env::var("AEGAEON_DATABASE_URL")
        .map_err(|_| "AEGAEON_DATABASE_URL must be configured")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .map_err(|_| "registration preflight database connection failed")?;
    let result =
        aegaeon_server::dcr_persistence::strict_registration_metadata_preflight(&pool).await;
    pool.close().await;
    let report = result.map_err(|_| "registration preflight database inspection failed")?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &report)
        .map_err(|_| "registration preflight report could not be written")?;
    writeln!(output).map_err(|_| "registration preflight report could not be written")?;
    Ok(report.findings.is_empty())
}
