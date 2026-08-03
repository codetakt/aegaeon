use std::future::Future;

#[path = "background_tasks/cleanup.rs"]
mod cleanup;
#[path = "background_tasks/runtime_config.rs"]
mod runtime_config;

use aegaeon_server::runtime_restart::{RuntimeRestartRequest, RuntimeRestartState};
use aegaeon_server::web::AppState;

pub(super) const CLEANUP_TASK_REQUEST_ID: &str = "runtime-cleanup";

pub(super) use runtime_config::{
    spawn_runtime_authority_notification_listener_task, spawn_runtime_config_monitor_task,
};

pub(super) fn spawn_cleanup_task(state: &AppState, cleanup_interval_secs: u64) {
    cleanup::spawn_cleanup_task(state, cleanup_interval_secs);
}

pub(super) fn spawn_supervised_runtime_task(
    runtime_restart: RuntimeRestartState,
    issuer_host: String,
    request_id: &'static str,
    component: &'static str,
    task: impl Future<Output = ()> + Send + 'static,
) {
    let handle = tokio::spawn(task);
    tokio::spawn(async move {
        match handle.await {
            Ok(()) if runtime_restart.is_requested() => {
                tracing::debug!(
                    target: "runtime_background_task",
                    issuer_host = %issuer_host,
                    component,
                    "runtime background task stopped after restart request"
                );
            }
            Ok(()) => {
                tracing::error!(
                    target: "runtime_background_task",
                    issuer_host = %issuer_host,
                    component,
                    "runtime background task returned unexpectedly; requesting graceful restart"
                );
                runtime_restart.request_restart(
                    RuntimeRestartRequest::runtime_authority_unavailable(
                        request_id,
                        issuer_host,
                        component,
                    ),
                );
            }
            Err(error) => {
                tracing::error!(
                    target: "runtime_background_task",
                    issuer_host = %issuer_host,
                    component,
                    error = %error,
                    "runtime background task failed; requesting graceful restart"
                );
                runtime_restart.request_restart(
                    RuntimeRestartRequest::runtime_authority_unavailable(
                        request_id,
                        issuer_host,
                        component,
                    ),
                );
            }
        }
    });
}
