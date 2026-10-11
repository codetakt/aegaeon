//! New report reservation, configuration identities and retained failures.
use super::{cli::Args, runner::run_load_test};
use anyhow::{ensure, Context, Result};
use std::io::{Seek, SeekFrom, Write};
use tracing::info;

pub(super) async fn execute(args: Args) -> Result<()> {
    let mut report = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.report_file)
        .context("cannot create a new report file")?;
    report.write_all(b"{\"schema_version\":2,\"complete\":false,\"stage\":\"setup\"}\n")?;
    report.sync_all()?;
    let config = match args.config() {
        Ok(config) => config,
        Err(error) => {
            write_report(
                &mut report,
                &serde_json::json!({"schema_version":2,"complete":false,"stage":"setup","error":error.to_string()}),
            )?;
            return Err(error);
        }
    };
    let mut results = run_load_test(config.clone(), &args.report_file, args.report_id).await?;
    if let Err(error) = results.validate_complete() {
        results.completion_errors.push(error.to_string());
    }
    results.print_summary(config.target_rps);
    write_report(&mut report, &results)?;
    ensure!(
        results.meets_slos(config.target_rps),
        "load test failed completeness or unchanged SLO thresholds; failed report preserved"
    );
    info!("Load test completed successfully");
    Ok(())
}

pub(super) fn write_report(file: &mut std::fs::File, value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
