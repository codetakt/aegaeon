//! Worker lifecycle, warmup, measured accounting and memory observation.
use aegaeon_loadtest::{
    profile::{required_env, sha256},
    scenarios::ScenarioExecutor,
    LoadTestConfig, LoadTestResults, ReportIdentity, TestScenario,
};
use anyhow::{ensure, Context, Result};
use num_traits::ToPrimitive;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::{
    sync::RwLock,
    task::JoinHandle,
    time::{interval, sleep},
};
use tracing::info;

pub(super) async fn run_load_test(
    config: LoadTestConfig,
    report_path: &str,
    report_id: Option<uuid::Uuid>,
) -> Result<LoadTestResults> {
    let mut initial = LoadTestResults::try_new()?;
    initial.selected_scenario = Some(config.scenario.clone());
    initial.warmup_requested = !config.warmup_duration.is_zero();
    let setup = (|| -> Result<ScenarioExecutor> {
        config.validate()?;
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
        let delay = config.worker_interval()?;
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

pub(super) fn report_identity(
    config: &LoadTestConfig,
    path: &str,
    report_id: Option<uuid::Uuid>,
) -> Result<ReportIdentity> {
    aegaeon_loadtest::url_validation::validate_report_urls(
        &config.target_url,
        config.discovery_expected_issuer.as_deref(),
    )?;
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
