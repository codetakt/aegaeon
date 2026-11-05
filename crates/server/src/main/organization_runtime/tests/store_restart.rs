//! Actual production startup/work across owned store restart and rollback barriers.
//! Python owns only the fixture processes; no production restart API is exposed.
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path, time::Instant};

const CASE: &str = "AEGAEON_TEST_ORGANIZATION_STORE_RESTART_CASE";
const DIRECTORY: &str = "AEGAEON_TEST_ORGANIZATION_STORE_RESTART_DIRECTORY";
const EXPECT: &str = "AEGAEON_TEST_ORGANIZATION_STORE_RESTART_EXPECT";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    configuration: Value,
    issuer_host: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    version: u32,
    nonce: Uuid,
    phase: String,
    success: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Heartbeat {
    version: u32,
    nonce: Uuid,
    sequence: u64,
}

fn private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let temporary = path.with_extension("partial");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

async fn barrier(directory: &Path, index: usize, case: &str, phase: &str) -> Result<()> {
    let nonce = Uuid::new_v4();
    private_json(
        &directory.join(format!("request-{index}.json")),
        &json!({"version":1,"nonce":nonce,"phase":phase,"case":case}),
    )?;
    let reply = directory.join(format!("reply-{index}.json"));
    let heartbeat = directory.join(format!("heartbeat-{index}.json"));
    let started = Instant::now();
    let mut last_progress = started;
    let mut sequence = 0;
    loop {
        if reply.exists() {
            let reply: Reply = serde_json::from_slice(&std::fs::read(&reply)?)?;
            ensure!(
                reply.version == 1 && reply.nonce == nonce && reply.phase == phase && reply.success,
                "owned restart fixture refused its exact barrier"
            );
            return Ok(());
        }
        if heartbeat.exists() {
            let progress: Heartbeat = serde_json::from_slice(&std::fs::read(&heartbeat)?)?;
            ensure!(
                progress.version == 1 && progress.nonce == nonce && progress.sequence >= sequence,
                "owned restart fixture heartbeat differs"
            );
            if progress.sequence > sequence {
                sequence = progress.sequence;
                last_progress = Instant::now();
            }
        }
        ensure!(
            started.elapsed() < Duration::from_secs(300)
                && last_progress.elapsed() < Duration::from_secs(30),
            "owned restart fixture barrier deadline"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn prepared(directory: &Path) -> Result<Prepared> {
    let saved: Saved =
        serde_json::from_slice(&std::fs::read(directory.join("configuration.json"))?)?;
    let fixture: Value = serde_json::from_slice(&std::fs::read(std::env::var(
        "AEGAEON_TEST_ORGANIZATION_STARTUP_FIXTURE",
    )?)?)?;
    let token = fixture["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fixture token endpoint missing"))?;
    Prepared::new(
        Configuration::parse(&serde_json::to_vec(&saved.configuration)?)?,
        saved.issuer_host,
        BootstrapConfig::try_from_env()?,
        token.into(),
    )
}

async fn read_environment(environment: Uuid, pool: &PgPool) -> Result<()> {
    let owner = crate::organizations::request_work::async_store::current_epoch_owner(environment)?;
    let mut connection = owner.connection(pool).await?;
    let found: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.environments WHERE id=$1")
        .bind(environment)
        .fetch_one(connection.as_mut()?)
        .await?;
    ensure!(
        found == environment,
        "owned work selected another Environment"
    );
    connection.release().await;
    Ok(())
}

async fn read_runtime_stores(state: crate::web::AppState) -> Result<()> {
    read_environment(state.environment_id, &state.db_pool).await?;
    // Reuse the runtime's actual token-store facade/client. This GET has no
    // application-state effect and exercises more than the witness observer.
    let missing = state
        .tokens
        .store
        .try_get_bearer_meta_async("owned-store-restart-absent-token".into())
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(
        missing.is_none(),
        "owned fixture unexpectedly has bearer metadata"
    );
    Ok(())
}

async fn complete_work(
    dispatcher: &EnvironmentDispatcher,
    state: crate::web::AppState,
) -> Result<()> {
    dispatcher
        .start(CapacityClass::Ordinary, move || read_runtime_stores(state))?
        .result()
        .await??;
    Ok(())
}

async fn build_and_complete(prepared: Prepared) -> Result<()> {
    let (runtime, dispatcher) = prepared.build().await?;
    let pool = runtime.state.db_pool.clone();
    let result = complete_work(&dispatcher, runtime.state.clone()).await;
    tokio::time::timeout(Duration::from_secs(10), pool.close()).await?;
    result
}

#[test]
#[ignore = "requires owned independent TLS stores and bounded external restart fixture"]
fn organization_production_store_restart_acceptance() -> anyhow::Result<()> {
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.worker_threads(2);
    with_environment(runtime, || async {
        let case = std::env::var(CASE)?;
        ensure!(
            matches!(
                case.as_str(),
                "postgres"
                    | "redis"
                    | "postgres-rollback"
                    | "redis-rollback"
                    | "pending-postgres"
                    | "pending-redis"
            ),
            "unknown owned restart case"
        );
        let directory = PathBuf::from(std::env::var(DIRECTORY)?);
        ensure!(
            directory.is_absolute(),
            "owned restart directory must be absolute"
        );
        let super::fixture::Context {
            prepared: first,
            mut control,
            deployment,
            scope,
            initialized,
            configuration,
            ..
        } = super::fixture::prepare(false).await?;
        private_json(
            &directory.join("configuration.json"),
            &Saved {
                configuration: serde_json::from_slice(&configuration)?,
                issuer_host: initialized.issuer_host,
            },
        )?;
        let result = async {
            if case.starts_with("pending-") {
                let (runtime, dispatcher) = first.build().await?;
                let pool = runtime.state.db_pool.clone();
                let state = runtime.state.clone();
                let (entered, entered_rx) = tokio::sync::oneshot::channel();
                let (release, release_rx) = tokio::sync::oneshot::channel();
                let execution = dispatcher.start(CapacityClass::Ordinary, move || async move {
                    read_runtime_stores(state).await?;
                    entered
                        .send(())
                        .map_err(|_| anyhow::anyhow!("pending fixture lost its observer"))?;
                    release_rx.await?;
                    Ok::<_, anyhow::Error>(())
                })?;
                tokio::time::timeout(Duration::from_secs(10), entered_rx).await??;
                let parent = serde_json::to_value(control.pending(deployment).await?)?;
                let child =
                    serde_json::to_value(control.environment_maintenance()?.pending(scope).await?)?;
                ensure!(
                    parent["state"]["pending"] == 1 && child["state"]["pending"] == 1,
                    "actual work was not durably pending"
                );
                barrier(&directory, 1, &case, "pending").await?;
                ensure!(
                    parent == serde_json::to_value(control.pending(deployment).await?)?
                        && child
                            == serde_json::to_value(
                                control.environment_maintenance()?.pending(scope).await?
                            )?,
                    "restart probe changed the existing pending owner"
                );
                release
                    .send(())
                    .map_err(|_| anyhow::anyhow!("pending fixture owner disappeared"))?;
                ensure!(
                    tokio::time::timeout(Duration::from_secs(15), execution.result())
                        .await?
                        .is_err(),
                    "work spanning an unaccepted store restart completed"
                );
                tokio::time::timeout(Duration::from_secs(10), pool.close()).await?;
                ensure!(
                    control.pending(deployment).await?.state.pending == 1
                        && control
                            .environment_maintenance()?
                            .pending(scope)
                            .await?
                            .state
                            .pending
                            == 1,
                    "uncertain restarted work was silently cleared"
                );
                barrier(&directory, 2, &case, "complete").await?;
            } else {
                let rollback = case.ends_with("-rollback");
                if rollback {
                    build_and_complete(first).await?;
                    ensure!(control.pending(deployment).await?.state.pending == 0);
                    barrier(&directory, 1, &case, "snapshot").await?;
                } else {
                    let (runtime, dispatcher) = first.build().await?;
                    let pool = runtime.state.db_pool.clone();
                    let live_result = async {
                        complete_work(&dispatcher, runtime.state.clone()).await?;
                        ensure!(
                            control.pending(deployment).await?.state.pending == 0
                                && control
                                    .environment_maintenance()?
                                    .pending(scope)
                                    .await?
                                    .state
                                    .pending
                                    == 0
                        );
                        // Keep this runtime, dispatcher, token client and state
                        // pool alive and idle through the physical restart.
                        barrier(&directory, 1, &case, "restart").await?;
                        ensure!(
                            !pool.is_closed(),
                            "live runtime pool was closed before restart work"
                        );
                        complete_work(&dispatcher, runtime.state.clone()).await
                    }
                    .await;
                    tokio::time::timeout(Duration::from_secs(10), pool.close()).await?;
                    live_result?;
                }
                build_and_complete(prepared(&directory)?).await?;
                ensure!(
                    control.pending(deployment).await?.state.pending == 0
                        && control
                            .environment_maintenance()?
                            .pending(scope)
                            .await?
                            .state
                            .pending
                            == 0
                );
                if rollback {
                    // Fresh probe processes each perform one actual constructor
                    // attempt; a closed process-wide class cannot mask retries.
                    barrier(&directory, 2, &case, "restore").await?;
                } else {
                    private_json(
                        &directory.join("outcomes.json"),
                        &json!({
                            "version":1,"case":case,
                            "same_runtime_work_after_restart":true,
                            "rebuilt_runtime_work_after_restart":true,
                            "application_postgres_read":true,
                            "application_token_store_read":"try_get_bearer_meta_async"
                        }),
                    )?;
                }
                barrier(&directory, if rollback { 3 } else { 2 }, &case, "complete").await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let cleanup = control.close().await.map_err(anyhow::Error::from);
        result.and(cleanup)
    })
}

#[test]
#[ignore = "requires saved owned fixture configuration; exactly one startup attempt per process"]
fn organization_production_store_restart_probe() -> anyhow::Result<()> {
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.worker_threads(2);
    with_environment(runtime, || async {
        crate::install_rustls_crypto_provider();
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_test_writer()
            .try_init();
        let directory = PathBuf::from(std::env::var(DIRECTORY)?);
        ensure!(
            std::env::var(EXPECT)? == "refuse",
            "unknown restart probe expectation"
        );
        let candidate = prepared(&directory)?;
        match candidate.build().await {
            Ok((runtime, _)) => {
                tokio::time::timeout(Duration::from_secs(10), runtime.state.db_pool.close())
                    .await?;
                anyhow::bail!("restored/pending store unexpectedly admitted production startup");
            }
            Err(_) => println!("store-restart-probe: attempted=1 refused=1"),
        }
        Ok(())
    })
}
