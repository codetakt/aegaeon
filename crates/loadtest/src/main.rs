#![forbid(unsafe_code)]
use aegaeon_loadtest::{
    scenarios::ScenarioExecutor, LoadTestConfig, LoadTestResults, TestScenario,
};
use anyhow::Result;
use clap::Parser;
use num_traits::ToPrimitive;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "aegaeon-loadtest")]
#[command(about = "Load testing tool for Aegaeon identity provider", long_about = None)]
struct Args {
    /// Target server URL
    #[arg(short, long, default_value = "http://localhost:8080")]
    url: String,

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

    /// Target requests per second
    #[arg(short, long, default_value_t = 100.0)]
    rps: f64,

    /// Spawn rate (users per second) - alias for rps
    #[arg(long = "spawn-rate", alias = "spawn_rate")]
    spawn_rate: Option<f64>,

    /// Warmup duration in seconds
    #[arg(long, default_value_t = 10)]
    warmup: u64,

    /// Report output file (JSON format)
    #[arg(long = "report-file", alias = "report_file")]
    report_file: Option<String>,

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

    // Initialize logging
    let filter = if args.debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    // Parse alternative arguments
    let workers = args.users.unwrap_or(args.workers);
    let rps = args.spawn_rate.unwrap_or(args.rps);

    // Parse run_time if provided (supports "60s", "5m" format)
    let duration = if let Some(run_time) = args.run_time {
        parse_duration(&run_time).unwrap_or_else(|_| Duration::from_secs(args.duration))
    } else {
        Duration::from_secs(args.duration)
    };

    // Create configuration
    let config = LoadTestConfig {
        target_url: args.url.clone(),
        workers,
        duration,
        target_rps: rps,
        warmup_duration: Duration::from_secs(args.warmup),
        scenario: args.scenario.into(),
        debug: args.debug,
    };

    info!("Starting load test");
    info!("Target: {}", config.target_url);
    info!("Workers: {}", config.workers);
    info!("Duration: {:?}", config.duration);
    info!("Target RPS: {}", config.target_rps);
    info!("Scenario: {:?}", config.scenario);

    let target_rps = config.target_rps;

    // Run load test
    let results = run_load_test(config).await?;

    // Print results
    results.print_summary(target_rps);

    // Save report to file if specified
    if let Some(report_file) = args.report_file {
        let report_json = serde_json::to_string_pretty(&results)?;
        std::fs::write(&report_file, report_json)?;
        info!("Report saved to: {}", report_file);
    }

    // Check if SLOs are met
    if !results.meets_slos(target_rps) {
        error!("Load test failed to meet SLOs");
        std::process::exit(1);
    }

    info!("Load test completed successfully");
    Ok(())
}

type ScenarioOutcome = (TestScenario, bool, u64);

async fn run_load_test(config: LoadTestConfig) -> Result<LoadTestResults> {
    let results = Arc::new(RwLock::new(LoadTestResults::try_new()?));
    let memory_monitor_handle = spawn_memory_monitor(results.clone());

    run_warmup_phase(&config).await;

    info!("Starting main test phase");
    let test_start = Instant::now();
    let test_end = test_start + config.duration;
    let worker_delay = calculate_worker_delay(&config);
    let handles = spawn_workers(&config, &results, test_end, worker_delay);

    wait_for_workers(handles).await;
    memory_monitor_handle.abort();

    finalize_results(&results, test_start.elapsed()).await
}

fn spawn_memory_monitor(results: Arc<RwLock<LoadTestResults>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut sys = System::new_all();
        let mut memory_interval = interval(Duration::from_secs(1));
        let pid = Pid::from_u32(std::process::id());

        loop {
            memory_interval.tick().await;
            sys.refresh_processes(ProcessesToUpdate::Some(&[pid]));

            if let Some(process) = sys.process(pid) {
                let memory_mb = process
                    .memory()
                    .to_f64()
                    .map_or(0.0, |memory| memory / 1024.0 / 1024.0);
                results.write().await.record_memory_sample(memory_mb);
            }
        }
    })
}

async fn run_warmup_phase(config: &LoadTestConfig) {
    if config.warmup_duration.is_zero() {
        return;
    }

    info!("Starting warmup phase ({:?})", config.warmup_duration);
    let warmup_end = Instant::now() + config.warmup_duration;

    while Instant::now() < warmup_end {
        let Ok(mut executor) = ScenarioExecutor::new(config.target_url.clone()) else {
            error!("failed to initialize loadtest scenario executor during warmup");
            break;
        };

        let _ = execute_warmup_scenario(&mut executor, config.scenario.clone()).await;
        sleep(Duration::from_millis(100)).await;
    }

    info!("Warmup phase completed");
}

async fn execute_warmup_scenario(
    executor: &mut ScenarioExecutor,
    scenario: TestScenario,
) -> Result<(bool, u64)> {
    match scenario {
        TestScenario::Smoke => executor
            .smoke_flow(0)
            .await
            .map(|(_, success, latency)| (success, latency)),
        TestScenario::AuthorizationCode => executor.authorization_code_flow().await,
        TestScenario::Introspection => executor.introspection_flow().await,
        TestScenario::Revocation => executor.revocation_flow().await,
        TestScenario::DPoP => executor.dpop_flow().await,
        TestScenario::Userinfo => executor.userinfo_flow().await,
        TestScenario::Discovery => executor.discovery_flow().await,
        TestScenario::Jwks => executor.jwks_flow().await,
        TestScenario::PAR => executor.par_flow().await,
        TestScenario::PolicyMixed => executor
            .policy_mixed_flow(0)
            .await
            .map(|(_scenario, success, latency)| (success, latency)),
        TestScenario::KeyRotation => executor.key_rotation_flow().await,
        TestScenario::Mixed => executor
            .mixed_flow(0)
            .await
            .map(|(_scenario, success, latency)| (success, latency)),
    }
}

fn calculate_worker_delay(config: &LoadTestConfig) -> Duration {
    let delay_between_requests = Duration::from_secs_f64(1.0 / config.target_rps);
    let worker_count = u32::try_from(config.workers).unwrap_or(u32::MAX);
    delay_between_requests * worker_count
}

fn spawn_workers(
    config: &LoadTestConfig,
    results: &Arc<RwLock<LoadTestResults>>,
    test_end: Instant,
    worker_delay: Duration,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    for worker_id in 0..config.workers {
        let worker_config = config.clone();
        let worker_results = results.clone();
        handles.push(tokio::spawn(async move {
            run_worker(
                &worker_config,
                &worker_results,
                test_end,
                worker_delay,
                worker_id,
            )
            .await;
        }));
    }

    handles
}

async fn run_worker(
    config: &LoadTestConfig,
    results: &Arc<RwLock<LoadTestResults>>,
    test_end: Instant,
    worker_delay: Duration,
    worker_id: usize,
) {
    let Ok(mut executor) = ScenarioExecutor::new(config.target_url.clone()) else {
        error!("failed to initialize loadtest scenario executor");
        return;
    };
    let mut iteration = 0u64;

    sleep(initial_worker_delay(worker_id)).await;

    while Instant::now() < test_end {
        let request_start = Instant::now();
        let (scenario, success, latency_ms) =
            execute_scenario(&mut executor, config.scenario.clone(), iteration).await;

        results
            .write()
            .await
            .record_request(
                latency_ms,
                success,
                scenario_error_label(&scenario, success),
            )
            .await;

        iteration += 1;
        if let Some(remaining) = worker_delay.checked_sub(request_start.elapsed()) {
            sleep(remaining).await;
        }
    }
}

fn initial_worker_delay(worker_id: usize) -> Duration {
    let delay_millis = u64::try_from(worker_id)
        .unwrap_or(u64::MAX / 100)
        .saturating_mul(100);
    Duration::from_millis(delay_millis)
}

async fn execute_scenario(
    executor: &mut ScenarioExecutor,
    scenario: TestScenario,
    iteration: u64,
) -> ScenarioOutcome {
    match scenario {
        TestScenario::Smoke => {
            executor
                .smoke_flow(iteration)
                .await
                .unwrap_or((TestScenario::Smoke, false, 0))
        }
        TestScenario::AuthorizationCode => scenario_outcome(
            TestScenario::AuthorizationCode,
            executor.authorization_code_flow().await,
        ),
        TestScenario::Introspection => scenario_outcome(
            TestScenario::Introspection,
            executor.introspection_flow().await,
        ),
        TestScenario::Revocation => {
            scenario_outcome(TestScenario::Revocation, executor.revocation_flow().await)
        }
        TestScenario::DPoP => scenario_outcome(TestScenario::DPoP, executor.dpop_flow().await),
        TestScenario::Userinfo => {
            scenario_outcome(TestScenario::Userinfo, executor.userinfo_flow().await)
        }
        TestScenario::Discovery => {
            scenario_outcome(TestScenario::Discovery, executor.discovery_flow().await)
        }
        TestScenario::Jwks => scenario_outcome(TestScenario::Jwks, executor.jwks_flow().await),
        TestScenario::PAR => scenario_outcome(TestScenario::PAR, executor.par_flow().await),
        TestScenario::PolicyMixed => executor.policy_mixed_flow(iteration).await.unwrap_or((
            TestScenario::PolicyMixed,
            false,
            0,
        )),
        TestScenario::KeyRotation => scenario_outcome(
            TestScenario::KeyRotation,
            executor.key_rotation_flow().await,
        ),
        TestScenario::Mixed => {
            executor
                .mixed_flow(iteration)
                .await
                .unwrap_or((TestScenario::Mixed, false, 0))
        }
    }
}

fn scenario_outcome(scenario: TestScenario, outcome: Result<(bool, u64)>) -> ScenarioOutcome {
    let scenario_for_success = scenario.clone();
    outcome
        .map(|(success, latency)| (scenario_for_success, success, latency))
        .unwrap_or((scenario, false, 0))
}

fn scenario_error_label(scenario: &TestScenario, success: bool) -> Option<String> {
    if success {
        None
    } else {
        Some(format!("{scenario:?}_error"))
    }
}

async fn wait_for_workers(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.await;
    }
}

async fn finalize_results(
    results: &Arc<RwLock<LoadTestResults>>,
    test_duration: Duration,
) -> Result<LoadTestResults> {
    let mut final_results = results.write().await;
    final_results.finalize(test_duration).await;
    Ok(final_results.clone())
}

fn parse_duration(s: &str) -> Result<Duration> {
    // Parse duration strings like "60s", "5m", "1h"
    if let Ok(secs) = s.parse::<u64>() {
        // Plain number - interpret as seconds
        return Ok(Duration::from_secs(secs));
    }

    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow::anyhow!("Empty duration string"));
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid number in duration: {num_str}"))?;

    match unit {
        "s" => Ok(Duration::from_secs(num)),
        "m" => Ok(Duration::from_secs(num * 60)),
        "h" => Ok(Duration::from_secs(num * 3600)),
        _ => Err(anyhow::anyhow!(
            "Unknown duration unit: {unit}. Use 's', 'm', or 'h'"
        )),
    }
}
