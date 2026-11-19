//! Continuous bounded polling on one selected Environment. No inbound listener.
use super::*;
use crate::organizations::notification_worker::Configuration as WorkerConfiguration;
use std::{future::Future, path::Path, sync::Arc};

/// Run until SIGINT/SIGTERM, finishing the bounded current attempt before exit.
/// Each process owns one worker ID; attempts, retries and fences live in SQL.
///
/// # Errors
/// Refuses private configuration, selected-runtime startup or unconfirmed cleanup.
pub async fn run_notification_worker(path: &Path, once: bool) -> Result<()> {
    crate::install_rustls_crypto_provider();
    let configuration = WorkerConfiguration::load(path)
        .map_err(|_| anyhow::anyhow!("notification worker configuration refused"))?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let prepared = Prepared::from_environment().await?;
    let trust = prepared.delivery_trust.clone();
    let (runtime, dispatcher) = prepared.build().await?;
    run(
        runtime,
        dispatcher,
        configuration,
        trust,
        once,
        async move {
            #[cfg(unix)]
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
        },
    )
    .await
}

pub(super) async fn run(
    runtime: BuiltServerRuntime,
    dispatcher: EnvironmentDispatcher,
    configuration: WorkerConfiguration,
    trust: Trust,
    once: bool,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let state = Arc::new(runtime.state);
    let keys = Arc::new(configuration);
    let trust = Arc::new(trust);
    let worker = Uuid::new_v4();
    let lifecycle = dispatcher.deployment();
    let pool = state.db_pool.clone();
    tokio::pin!(shutdown);
    let result = async {
        let mut cycles = 0u64;
        loop {
            if once && cycles >= 16 { return Ok(()); }
            // Shutdown does not drop an in-flight admission: at most one finite
            // cycle finishes before this select is polled again.
            tokio::select! {
                biased;
                () = &mut shutdown => return Ok(()),
                () = state.runtime_restart.notified() => anyhow::bail!("notification runtime requires restart"),
                () = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
            let current = state.clone();
            let keys = keys.clone();
            let trust = trust.clone();
            let execution = dispatcher.start(CapacityClass::Ordinary, move || async move {
                current.process_notification(worker, &keys.ring, &keys.credential, &trust).await
            })?;
            match execution.result().await? {
                Ok(tick) => {
                    if once || cycles.is_multiple_of(30) || tick.claimed || tick.retired.total() != 0 || tick.collected != 0 {
                        tracing::info!(target: "notification_worker", event="notification_cycle_completed",
                            claimed=tick.claimed, retired=tick.retired.total(), collected=tick.collected,
                            retired_expired=tick.retired.expired,
                            retired_exhausted=tick.retired.exhausted,
                            retired_generation_changed=tick.retired.generation_changed,
                            pending=tick.statistics.pending, leased=tick.statistics.leased,
                            oldest_age_seconds=tick.statistics.oldest_age_seconds,
                            outcome=tick.outcome.unwrap_or("idle"),
                            retry_status=tick.retry_status.unwrap_or("idle"));
                    }
                    if once && !tick.claimed { return Ok(()); }
                }
                Err(()) => {
                    // No URL, message, recipient, key, ciphertext or source error.
                    tracing::warn!(target: "notification_worker", outcome="unavailable", "notification cycle incomplete");
                    if once { anyhow::bail!("notification batch incomplete"); }
                }
            }
            cycles = cycles.wrapping_add(1);
        }
    }.await;
    tokio::time::timeout(Duration::from_secs(10), async {
        lifecycle.close().await;
        crate::organizations::lifecycle::close_pool(&pool).await;
    })
    .await
    .map_err(|_| anyhow::anyhow!("notification worker cleanup incomplete"))?;
    result
}

/// Explicitly replace one currently authorized notification; sends no HTTP.
/// Repeat an uncertain invocation with the same operation ID and exact input.
///
/// # Errors
/// Refuses private configuration, current purpose/credential, revision mismatch,
/// unavailable storage or unconfirmed cleanup.
pub async fn run_notification_reissue(
    path: &Path,
    input: crate::web::NotificationReissueRequest,
) -> Result<crate::web::NotificationReissueResult> {
    crate::install_rustls_crypto_provider();
    let configuration = WorkerConfiguration::load(path)
        .map_err(|_| anyhow::anyhow!("notification worker configuration refused"))?;
    let prepared = Prepared::from_environment().await?;
    let (runtime, dispatcher) = prepared.build().await?;
    let pool = runtime.state.db_pool.clone();
    let lifecycle = dispatcher.deployment();
    let execution = dispatcher.start(CapacityClass::Ordinary, move || async move {
        runtime
            .state
            .reissue_notification(&input, &configuration.credential)
            .await
    });
    let result = match execution {
        Ok(execution) => execution
            .result()
            .await
            .map_err(anyhow::Error::from)
            .and_then(|value| value.map_err(|()| anyhow::anyhow!("notification reissue refused"))),
        Err(error) => Err(error.into()),
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        lifecycle.close().await;
        crate::organizations::lifecycle::close_pool(&pool).await;
    })
    .await
    .map_err(|_| anyhow::anyhow!("notification worker cleanup incomplete"))?;
    result.map_err(|_| anyhow::anyhow!("notification reissue unavailable"))
}
