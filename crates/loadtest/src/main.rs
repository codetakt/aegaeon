#![forbid(unsafe_code)]
use aegaeon_loadtest::{
    profile::{required_env, sha256},
    scenarios::ScenarioExecutor,
    LoadTestConfig, LoadTestResults, ReportIdentity, TestScenario,
};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use num_traits::ToPrimitive;
use std::time::{Duration, Instant};
use std::{
    io::{Seek, SeekFrom, Write},
    sync::Arc,
};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "aegaeon-loadtest")]
#[command(about = "Load testing tool for Aegaeon identity provider", long_about = None)]
struct Args {
    /// Target server URL
    #[arg(short, long, default_value = "http://localhost:8080")]
    url: String,

    /// Canonical HTTPS issuer expected in public discovery metadata
    #[arg(long)]
    discovery_expected_issuer: Option<String>,

    /// Number of concurrent workers (alias for users)
    #[arg(short, long, default_value_t = 10)]
    workers: usize,

    /// Number of concurrent users (alias for workers)
    #[arg(long, alias = "users")]
    users: Option<usize>,

    /// Test duration in seconds
    #[arg(short, long, default_value_t = 60)]
    duration: u64,

    /// Test duration (alternative format, e.g., "60s", "5m")
    #[arg(long = "run-time", alias = "run_time")]
    run_time: Option<String>,

    /// Target scenario invocations per second
    #[arg(short, long, default_value_t = 100.0)]
    rps: f64,

    /// Spawn rate (users per second) - alias for rps
    #[arg(long = "spawn-rate", alias = "spawn_rate")]
    spawn_rate: Option<f64>,

    /// Warmup duration: numeric seconds or a duration such as 10s or 1m
    #[arg(long, default_value = "10")]
    warmup: String,

    /// Report output file (JSON format)
    #[arg(long = "report-file", alias = "report_file", required = true)]
    report_file: String,

    /// Report UUID chosen by an independent driver before launch
    #[arg(long)]
    report_id: Option<uuid::Uuid>,

    /// Test scenario
    #[arg(short, long, value_enum, default_value = "smoke")]
    scenario: CliScenario,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum CliScenario {
    Smoke,
    AuthCode,
    Introspection,
    Revocation,
    Dpop,
    Userinfo,
    Discovery,
    Jwks,
    Par,
    Mixed,
    PolicyMixed,
    KeyRotation,
}

impl From<CliScenario> for TestScenario {
    fn from(cli: CliScenario) -> Self {
        match cli {
            CliScenario::Smoke => TestScenario::Smoke,
            CliScenario::AuthCode => TestScenario::AuthorizationCode,
            CliScenario::Introspection => TestScenario::Introspection,
            CliScenario::Revocation => TestScenario::Revocation,
            CliScenario::Dpop => TestScenario::DPoP,
            CliScenario::Userinfo => TestScenario::Userinfo,
            CliScenario::Discovery => TestScenario::Discovery,
            CliScenario::Jwks => TestScenario::Jwks,
            CliScenario::Par => TestScenario::PAR,
            CliScenario::Mixed => TestScenario::Mixed,
            CliScenario::PolicyMixed => TestScenario::PolicyMixed,
            CliScenario::KeyRotation => TestScenario::KeyRotation,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(if args.debug {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        })
        .json()
        .init();
    // Reserve a new report before setup; a failed run cannot overwrite prior evidence.
    let mut report = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.report_file)
        .context("cannot create a new report file")?;
    report.write_all(b"{\"schema_version\":2,\"complete\":false,\"stage\":\"setup\"}\n")?;
    report.sync_all()?;
    let duration = match args.run_time.as_deref().map(parse_duration).transpose() {
        Ok(value) => value.unwrap_or(Duration::from_secs(args.duration)),
        Err(error) => {
            write_report(
                &mut report,
                &serde_json::json!({"schema_version":2,"complete":false,"stage":"setup","error":error.to_string()}),
            )?;
            return Err(error);
        }
    };
    let warmup_duration = match parse_duration(&args.warmup) {
        Ok(duration) => duration,
        Err(error) => {
            write_report(
                &mut report,
                &serde_json::json!({"schema_version":2,"complete":false,"stage":"setup","error":format!("invalid warmup: {error}")}),
            )?;
            return Err(error.context("invalid warmup duration"));
        }
    };
    let config = LoadTestConfig {
        target_url: args.url,
        discovery_expected_issuer: args.discovery_expected_issuer,
        workers: args.users.unwrap_or(args.workers),
        duration,
        target_rps: args.spawn_rate.unwrap_or(args.rps),
        warmup_duration,
        scenario: args.scenario.into(),
        debug: args.debug,
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

fn write_report(file: &mut std::fs::File, value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn validate_config(config: &LoadTestConfig) -> Result<()> {
    ensure!(
        config.workers > 0 && u32::try_from(config.workers).is_ok(),
        "worker count must be positive and representable"
    );
    ensure!(
        config.target_rps.is_finite() && config.target_rps > 0.0,
        "target invocation rate must be finite and positive"
    );
    ensure!(
        !config.duration.is_zero()
            && config.duration.as_secs() <= 86_400
            && config.warmup_duration.as_secs() <= 86_400,
        "run durations must be bounded and main duration positive"
    );
    let seconds =
        (f64::from(u32::try_from(config.workers).context("worker count must be representable")?))
            / config.target_rps;
    ensure!(
        seconds.is_finite() && seconds <= 86_400.0,
        "worker pacing interval exceeds bound"
    );
    Ok(())
}

fn report_identity(
    config: &LoadTestConfig,
    path: &str,
    report_id: Option<uuid::Uuid>,
) -> Result<ReportIdentity> {
    let report_id = report_id.unwrap_or_else(uuid::Uuid::new_v4);
    ensure!(
        report_id.get_version_num() == 4,
        "report identity must be UUIDv4"
    );
    let source_sha256 = required_env("AEG_LOADTEST_SOURCE_SHA256")?;
    ensure!(
        source_sha256.len() == 64
            && source_sha256
                .bytes()
                .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase()),
        "source identity must be the lowercase SHA256 of the frozen source manifest"
    );
    let binary = std::fs::read(std::env::current_exe()?)
        .context("cannot identify actual load generator binary")?;
    let config_json = serde_json::to_string(config)?;
    Ok(ReportIdentity {
        source_sha256,
        artifact_sha256: sha256(&binary),
        config_sha256: sha256(config_json.as_bytes()),
        config_json,
        report_id: report_id.to_string(),
        report_path: path.into(),
        profile_sha256: None,
        session_provenance_sha256: None,
    })
}

async fn run_load_test(
    config: LoadTestConfig,
    report_path: &str,
    report_id: Option<uuid::Uuid>,
) -> Result<LoadTestResults> {
    let mut initial = LoadTestResults::try_new()?;
    initial.selected_scenario = Some(config.scenario.clone());
    initial.warmup_requested = !config.warmup_duration.is_zero();
    let setup = (|| -> Result<ScenarioExecutor> {
        validate_config(&config)?;
        initial.identity = Some(report_identity(&config, report_path, report_id)?);
        let executor = ScenarioExecutor::for_scenario_with_discovery_issuer(
            config.target_url.clone(),
            &config.scenario,
            config.discovery_expected_issuer.as_deref(),
        )?;
        if let Some((profile, session)) = executor.supplier_identity() {
            let identity = initial
                .identity
                .as_mut()
                .context("missing report identity")?;
            identity.profile_sha256 = Some(profile);
            identity.session_provenance_sha256 = Some(session);
        }
        Ok(executor)
    })();
    let prototype = match setup {
        Ok(executor) => executor,
        Err(error) => {
            initial.completion_errors.push(error.to_string());
            return Ok(initial);
        }
    };
    let results = Arc::new(RwLock::new(initial));
    if config.warmup_duration.is_zero() || run_warmup_phase(&config, &prototype, &results).await? {
        info!("Starting main test phase");
        let memory_monitor = spawn_memory_monitor(results.clone());
        let start = Instant::now();
        let end = start + config.duration;
        let delay = Duration::from_secs_f64(
            f64::from(u32::try_from(config.workers).context("worker count must be representable")?)
                / config.target_rps,
        );
        let mut handles = Vec::new();
        for worker in 0..config.workers {
            let executor = prototype.fork_worker();
            let worker_config = config.clone();
            let worker_results = results.clone();
            handles.push(tokio::spawn(async move {
                run_worker(
                    &worker_config,
                    executor,
                    &worker_results,
                    end,
                    delay,
                    worker,
                )
                .await
            }));
        }
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => results
                    .write()
                    .await
                    .completion_errors
                    .push(error.to_string()),
                Err(error) => results
                    .write()
                    .await
                    .completion_errors
                    .push(format!("worker join failure: {error}")),
            }
        }
        results.write().await.finalize(start.elapsed()).await;
        memory_monitor.abort();
        match memory_monitor.await {
            Err(error) if error.is_cancelled() => {}
            Err(error) => results
                .write()
                .await
                .completion_errors
                .push(format!("memory monitor join failure: {error}")),
            Ok(()) => results
                .write()
                .await
                .completion_errors
                .push("memory monitor terminated early".into()),
        }
    }
    let result = results.read().await.clone();
    Ok(result)
}

fn spawn_memory_monitor(results: Arc<RwLock<LoadTestResults>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut sys = System::new_all();
        let pid = Pid::from_u32(std::process::id());
        let mut ticks = interval(Duration::from_secs(1));
        loop {
            ticks.tick().await;
            sys.refresh_processes(ProcessesToUpdate::Some(&[pid]));
            if let Some(process) = sys.process(pid) {
                if let Some(memory) = process.memory().to_f64() {
                    results
                        .write()
                        .await
                        .record_memory_sample(memory / 1024.0 / 1024.0);
                } else {
                    results
                        .write()
                        .await
                        .completion_errors
                        .push("load generator memory is not representable".into());
                }
            } else {
                results
                    .write()
                    .await
                    .completion_errors
                    .push("load generator memory sample unavailable".into());
            }
        }
    })
}

async fn run_warmup_phase(
    config: &LoadTestConfig,
    prototype: &ScenarioExecutor,
    results: &Arc<RwLock<LoadTestResults>>,
) -> Result<bool> {
    let mut executor = prototype.fork_worker();
    let end = Instant::now() + config.warmup_duration;
    let mut iteration = 0;
    while Instant::now() < end {
        record_invocation(&mut executor, &config.scenario, iteration, results, true).await?;
        iteration += 1;
        sleep(Duration::from_millis(100)).await;
    }
    let mut results = results.write().await;
    if let Err(error) = results
        .warmup_phase
        .validate(&config.scenario.required_legs())
    {
        results
            .completion_errors
            .push(format!("warmup failed: {error}"));
        return Ok(false);
    }
    Ok(true)
}

async fn run_worker(
    config: &LoadTestConfig,
    mut executor: ScenarioExecutor,
    results: &Arc<RwLock<LoadTestResults>>,
    end: Instant,
    delay: Duration,
    worker: usize,
) -> Result<()> {
    let mut iteration = 0;
    sleep(Duration::from_millis((worker as u64).saturating_mul(100))).await;
    while Instant::now() < end {
        let start = Instant::now();
        record_invocation(&mut executor, &config.scenario, iteration, results, false).await?;
        iteration += 1;
        if let Some(remaining) = delay.checked_sub(start.elapsed()) {
            sleep(remaining).await;
        }
    }
    Ok(())
}

async fn record_invocation(
    executor: &mut ScenarioExecutor,
    scenario: &TestScenario,
    iteration: u64,
    results: &Arc<RwLock<LoadTestResults>>,
    warmup: bool,
) -> Result<()> {
    let (leg, rejection) = scenario.leg(iteration);
    let start = Instant::now();
    let outcome = execute_scenario(executor, scenario, iteration).await;
    let latency = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (success, error) = match outcome {
        Ok((true, _)) => (true, None),
        Ok((false, _)) => (false, Some(format!("{leg}: scenario returned failure"))),
        Err(error) => (false, Some(format!("{leg}: {error}"))),
    };
    let http = executor.take_accounting();
    let mut results = results.write().await;
    let phase = if warmup {
        &mut results.warmup_phase
    } else {
        &mut results.main_phase
    };
    phase
        .legs
        .entry(leg)
        .or_default()
        .record(success, rejection);
    if let Err(error) = phase.http.merge(http) {
        phase.errors.push(error.to_string());
    }
    if warmup {
        if let Some(error) = error {
            phase.errors.push(error);
        }
    } else {
        results.record_request(latency, success, error).await;
    }
    if let Some(digest) = &executor.jwks_sha256 {
        if !results.jwks_sha256.contains(digest) {
            results.jwks_sha256.push(digest.clone());
        }
    }
    Ok(())
}

async fn execute_scenario(
    executor: &mut ScenarioExecutor,
    scenario: &TestScenario,
    iteration: u64,
) -> Result<(bool, u64)> {
    match scenario {
        TestScenario::Smoke => executor.smoke_flow(iteration).await.map(|(_, a, b)| (a, b)),
        TestScenario::AuthorizationCode => executor.authorization_code_flow().await,
        TestScenario::Introspection => executor.introspection_flow().await,
        TestScenario::Revocation => executor.revocation_flow().await,
        TestScenario::DPoP => executor.dpop_flow().await,
        TestScenario::Userinfo => executor.userinfo_flow().await,
        TestScenario::Discovery => executor.discovery_flow().await,
        TestScenario::Jwks => executor.jwks_flow().await,
        TestScenario::PAR => executor.par_flow().await,
        TestScenario::Mixed => executor.mixed_flow(iteration).await.map(|(_, a, b)| (a, b)),
        TestScenario::PolicyMixed => executor
            .policy_mixed_flow(iteration)
            .await
            .map(|(_, a, b)| (a, b)),
        TestScenario::KeyRotation => executor.key_rotation_flow(),
    }
}

fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    ensure!(!value.is_empty(), "empty duration");
    if let Ok(seconds) = value.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }
    let position = value.char_indices().last().context("empty duration")?.0;
    let (number, unit) = value.split_at(position);
    let count: u64 = number.parse().context("invalid duration number")?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => anyhow::bail!("unknown duration unit"),
    };
    Ok(Duration::from_secs(
        count.checked_mul(multiplier).context("duration overflow")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn warmup_accepts_legacy_seconds_and_driver_duration_syntax() {
        for (input, seconds) in [
            ("0", 0),
            ("1", 1),
            ("1s", 1),
            ("10s", 10),
            ("1m", 60),
            ("1h", 3600),
        ] {
            let args = Args::try_parse_from([
                "aegaeon-loadtest",
                "--report-file",
                "unused.json",
                "--warmup",
                input,
            ])
            .unwrap();
            assert_eq!(
                parse_duration(&args.warmup).unwrap(),
                Duration::from_secs(seconds)
            );
        }
        for input in ["bad", "5秒", "18446744073709551615h"] {
            let args = Args::try_parse_from([
                "aegaeon-loadtest",
                "--report-file",
                "unused.json",
                "--warmup",
                input,
            ])
            .unwrap();
            assert!(parse_duration(&args.warmup).is_err());
        }
    }
    #[test]
    fn explicit_report_uuid_and_discovery_issuer_are_parsed_without_transport_override() {
        let id = "12345678-1234-4234-8234-123456789abc";
        let args = Args::try_parse_from([
            "aegaeon-loadtest",
            "--url",
            "http://127.0.0.1:18095",
            "--discovery-expected-issuer",
            "https://issuer.example.test",
            "--report-file",
            "fresh.json",
            "--report-id",
            id,
        ])
        .unwrap();
        assert_eq!(args.url, "http://127.0.0.1:18095");
        assert_eq!(
            args.discovery_expected_issuer.as_deref(),
            Some("https://issuer.example.test")
        );
        assert_eq!(args.report_id.unwrap().to_string(), id);
        assert!(Args::try_parse_from([
            "aegaeon-loadtest",
            "--report-file",
            "fresh.json",
            "--report-id",
            "malformed"
        ])
        .is_err());
    }

    #[test]
    fn config_rejects_zero_and_nonfinite_execution_parameters() {
        let mut config = LoadTestConfig::default();
        assert!(validate_config(&config).is_ok());
        for rps in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            config.target_rps = rps;
            assert!(validate_config(&config).is_err());
        }
        config.target_rps = 1.0;
        config.workers = 0;
        assert!(validate_config(&config).is_err());
        assert!(parse_duration("18446744073709551615h").is_err());
        assert!(parse_duration("bad").is_err());
        assert!(parse_duration("5秒").is_err());
    }
}
