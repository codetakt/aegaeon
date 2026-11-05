use super::spawn_supervised_runtime_task;
use crate::runtime_configuration::DatabaseRuntimeConfiguration;
use crate::web::AppState;
use anyhow::Result;

#[path = "runtime_config/monitor.rs"]
mod monitor;
#[path = "runtime_config/notifications.rs"]
mod notifications;

use monitor::RuntimeConfigMonitor;

#[cfg(test)]
#[path = "runtime_config/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_config/notification_tests.rs"]
mod notification_tests;

/// Qualified startup assembly must replace its ordinary monitor and raw
/// notification listener with observed entries; this does not qualify supply.
pub(super) fn spawn_observed_runtime_config_monitor_task(
    state: &AppState,
    runtime_config: &DatabaseRuntimeConfiguration,
    dispatcher: crate::organizations::witness::deployment::dispatch::EnvironmentDispatcher,
    interval_secs: u64,
) -> Result<super::ObservedTask> {
    anyhow::ensure!(
        dispatcher.environment_id() == state.environment_id
            && runtime_config.environment_id == state.environment_id
            && runtime_config.issuer_host == state.runtime_authority.issuer_host()
            && crate::config::valid_runtime_sync_interval_secs(interval_secs)
            && tokio::runtime::Handle::try_current().is_ok()
            && crate::organizations::request_work::async_store::task_owner()?.is_none(),
        "observed monitor requires one Environment, a finite interval and no enclosing work"
    );
    let monitor = RuntimeConfigMonitor::from_state(state, runtime_config);
    let restart = monitor.runtime_restart().clone();
    let issuer_host = monitor.issuer_host().to_owned();
    Ok(super::owned::spawn(
        restart.clone(),
        issuer_host,
        "runtime_config_monitor",
        move |ready| {
            Box::pin(async move {
                let pass = move || {
                    let monitor = monitor.clone();
                    async move {
                        monitor.check_revision().await;
                        Ok(())
                    }
                };
                dispatcher
                    .start(
                        crate::organizations::request_work::CapacityClass::Ordinary,
                        pass.clone(),
                    )?
                    .result()
                    .await??;
                let _ = ready.send(());
                dispatcher
                    .run_periodic(interval_secs, restart, pass)
                    .await?;
                Ok(())
            })
        },
    ))
}

pub(super) const RUNTIME_CONFIG_MONITOR_REQUEST_ID: &str = "runtime-config-monitor";
pub(super) const RUNTIME_CONFIG_NOTIFICATION_REQUEST_ID: &str = "runtime-config-notifications";

/// Replace the ordinary listener when mounting the observed runtime. Notifications
/// never authorize work; every initial/reconnected/notified check is dispatched.
pub(super) fn spawn_observed_runtime_authority_notification_listener_task(
    state: &AppState,
    runtime_config: &DatabaseRuntimeConfiguration,
    dispatcher: crate::organizations::witness::deployment::dispatch::EnvironmentDispatcher,
) -> Result<super::ObservedTask> {
    anyhow::ensure!(
        dispatcher.environment_id() == state.environment_id
            && runtime_config.environment_id == state.environment_id
            && runtime_config.issuer_host == state.runtime_authority.issuer_host()
            && tokio::runtime::Handle::try_current().is_ok()
            && crate::organizations::request_work::async_store::task_owner()?.is_none(),
        "observed listener requires one Environment and no enclosing work"
    );
    let monitor = RuntimeConfigMonitor::from_state(state, runtime_config);
    let restart = monitor.runtime_restart().clone();
    let issuer_host = monitor.issuer_host().to_owned();
    let options = dispatcher.primary_options();
    Ok(super::owned::spawn(
        restart.clone(),
        issuer_host.clone(),
        "runtime_config_notifications",
        move |ready| {
            Box::pin(async move {
                let mut ready = Some(ready);
                notifications::run_with_options(options, &issuer_host, &restart, move || {
                    let monitor = monitor.clone();
                    let dispatcher = dispatcher.clone();
                    let ready = ready.take();
                    async move {
                        dispatcher
                            .start(
                                crate::organizations::request_work::CapacityClass::Ordinary,
                                move || async move {
                                    monitor.check_revision().await;
                                },
                            )?
                            .result()
                            .await?;
                        if let Some(ready) = ready {
                            let _ = ready.send(());
                        }
                        Ok(())
                    }
                })
                .await
            })
        },
    ))
}

pub(crate) fn spawn_runtime_config_monitor_task(
    state: &AppState,
    runtime_config: &DatabaseRuntimeConfiguration,
    interval_secs: u64,
) -> Result<()> {
    let monitor = RuntimeConfigMonitor::from_state(state, runtime_config);
    let runtime_restart = monitor.runtime_restart().clone();
    let issuer_host = monitor.issuer_host().to_string();

    spawn_supervised_runtime_task(
        runtime_restart,
        issuer_host,
        RUNTIME_CONFIG_MONITOR_REQUEST_ID,
        "runtime_config_monitor",
        async move {
            monitor.run(interval_secs).await;
        },
    );
    Ok(())
}

pub(crate) async fn spawn_runtime_authority_notification_listener_task(
    state: &AppState,
    runtime_config: &DatabaseRuntimeConfiguration,
) -> Result<()> {
    let monitor = RuntimeConfigMonitor::from_state(state, runtime_config);
    let runtime_restart = monitor.runtime_restart().clone();
    let issuer_host = monitor.issuer_host().to_string();
    let database_url = state.cfg.database.url().to_string();

    spawn_supervised_runtime_task(
        runtime_restart,
        issuer_host,
        RUNTIME_CONFIG_NOTIFICATION_REQUEST_ID,
        "runtime_config_notifications",
        async move {
            notifications::run_runtime_authority_notification_listener(database_url, monitor).await;
        },
    );
    Ok(())
}
