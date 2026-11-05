//! One production lifecycle for observed startup, HTTP and background drainage.
use super::*;
use crate::{runtime_restart::RuntimeRestartRequest, server_runtime::ObservedBackgroundTasks};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub(in crate::server_runtime) async fn serve(args: &super::super::Args) -> Result<()> {
    crate::install_rustls_crypto_provider();
    let prepared = Prepared::from_environment().await?;
    let address: std::net::SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (runtime, dispatcher) = prepared.build().await?;
    run(listener, runtime, dispatcher, async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

pub(super) async fn run(
    listener: tokio::net::TcpListener,
    runtime: BuiltServerRuntime,
    dispatcher: EnvironmentDispatcher,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let pool = runtime.state.db_pool.clone();
    let lifecycle = dispatcher.deployment();
    let restart = runtime.state.runtime_restart.clone();
    // This bound begins at actual shutdown, not at server launch. Expiry cannot
    // certify completion: the group Drop requests stop and pending remains.
    let result = tokio::select! {
        result = run_owned(listener, runtime, dispatcher, shutdown) => result,
        () = async { restart.notified().await; tokio::time::sleep(Duration::from_secs(45)).await; } => {
            Err(anyhow::anyhow!("observed HTTP/background shutdown incomplete"))
        }
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        lifecycle.close().await;
        pool.close().await;
    })
    .await
    .map_err(|_| anyhow::anyhow!("observed server pool cleanup incomplete"))?;
    result
}

async fn run_owned(
    listener: tokio::net::TcpListener,
    runtime: BuiltServerRuntime,
    dispatcher: EnvironmentDispatcher,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let background = ObservedBackgroundTasks::start(
        &runtime.state,
        &runtime.database_runtime_config,
        dispatcher.clone(),
        u64::from(
            runtime
                .database_runtime_config
                .state
                .policy
                .cleanup_interval_seconds,
        ),
        runtime.runtime_sync.config_monitor_interval_secs,
    )
    .await?;
    let restart = runtime.state.runtime_restart.clone();
    let issuer = runtime.database_runtime_config.issuer_host.clone();
    let app = crate::web::build_observed_router(runtime.state, dispatcher.deployment());
    let requested = Arc::new(AtomicBool::new(false));
    let signal = requested.clone();
    let stopping = restart.clone();
    let stopping_issuer = issuer.clone();
    let served = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        tokio::select! {
            () = stopping.notified() => {},
            () = shutdown => {
                signal.store(true, Ordering::SeqCst);
                stopping.request_restart(RuntimeRestartRequest::runtime_critical_mutation(
                    "server-shutdown", stopping_issuer, "requested_shutdown",
                ));
            }
        }
    })
    .await;
    if !restart.is_requested() {
        restart.request_restart(RuntimeRestartRequest::runtime_authority_unavailable(
            "server-lifecycle",
            issuer,
            "listener_stopped",
        ));
    }
    let drained = background.drain().await;
    served?;
    drained?;
    ensure!(
        requested.load(Ordering::SeqCst),
        "runtime authority requested server restart"
    );
    Ok(())
}
