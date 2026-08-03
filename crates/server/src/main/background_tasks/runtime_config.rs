use super::spawn_supervised_runtime_task;
use aegaeon_server::runtime_configuration::DatabaseRuntimeConfiguration;
use aegaeon_server::web::AppState;
use anyhow::Result;

#[path = "runtime_config/monitor.rs"]
mod monitor;
#[path = "runtime_config/notifications.rs"]
mod notifications;

use monitor::RuntimeConfigMonitor;

pub(super) const RUNTIME_CONFIG_MONITOR_REQUEST_ID: &str = "runtime-config-monitor";
pub(super) const RUNTIME_CONFIG_NOTIFICATION_REQUEST_ID: &str = "runtime-config-notifications";

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
