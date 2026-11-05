use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use crate::management::runtime_commands::{
    reconcile_stale_environment_runtime_commands, reconcile_stale_management_user_runtime_commands,
    runtime_command_stale_after,
};
use crate::web::AppState;
use sqlx::PgPool;

const CLEANUP_JOB_TIMEOUT_SECS: u64 = 30;

#[cfg(test)]
#[path = "cleanup/tests.rs"]
mod tests;

fn log_cleanup_failure(component: &'static str, error: impl std::fmt::Display) {
    tracing::error!(
        target: "cleanup",
        component,
        error = %error,
        "periodic cleanup failed"
    );
}

async fn run_cleanup_blocking(
    component: &'static str,
    timeout: Duration,
    failed: &AtomicBool,
    cleanup: impl FnOnce() -> Result<(), String> + Send + 'static,
) {
    match tokio::time::timeout(
        timeout,
        crate::organizations::request_work::async_store::blocking(cleanup),
    )
    .await
    {
        Ok(Ok(Ok(()))) => return,
        Ok(Ok(Err(error))) => log_cleanup_failure(component, error),
        Ok(Err(error)) => tracing::error!(
            target: "cleanup",
            component,
            error = %error,
            "periodic cleanup blocking task failed"
        ),
        Err(_) => tracing::warn!(
            target: "cleanup",
            component,
            timeout_secs = timeout.as_secs(),
            "periodic cleanup blocking task timed out"
        ),
    }
    failed.store(true, Ordering::Relaxed);
}

async fn run_async_cleanup(
    component: &'static str,
    timeout: Duration,
    failed: &AtomicBool,
    cleanup: impl std::future::Future<Output = Result<(), String>>,
) {
    if !matches!(tokio::time::timeout(timeout, cleanup).await, Ok(Ok(()))) {
        failed.store(true, Ordering::Relaxed);
        log_cleanup_failure(component, "asynchronous cleanup unavailable");
    }
}

async fn read_authorization_code_counters(
    issuer: Arc<crate::authcode::TokenIssuer>,
) -> Result<Result<(usize, usize), String>, tokio::time::error::Elapsed> {
    tokio::time::timeout(
        Duration::from_secs(CLEANUP_JOB_TIMEOUT_SECS),
        issuer.observation_counts_async(),
    )
    .await
}

async fn reconcile_stale_management_runtime_commands(
    pool: PgPool,
    environment_id: uuid::Uuid,
    stale_after: Duration,
) -> Result<u64, String> {
    let scoped = crate::organizations::request_work::async_store::task_owner()
        .map_err(|err| err.to_string())?
        .is_some();
    let result = if scoped {
        reconcile_stale_environment_runtime_commands(&pool, environment_id, stale_after).await
    } else {
        reconcile_stale_management_user_runtime_commands(&pool, stale_after).await
    };
    result.map_err(|err| err.to_string())
}

pub(super) fn spawn_cleanup_task(state: &AppState, cleanup_interval_secs: u64) {
    let state = state.clone();
    let runtime_restart = state.runtime_restart.clone();
    super::spawn_supervised_runtime_task(
        runtime_restart.clone(),
        state.runtime_authority.issuer_host().to_owned(),
        super::CLEANUP_TASK_REQUEST_ID,
        "cleanup",
        async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(cleanup_interval_secs.max(1)));
            loop {
                tokio::select! {
                    () = runtime_restart.notified() => {
                        tracing::info!(target: "cleanup", "periodic cleanup stopped after runtime restart request");
                        break;
                    }
                    _ = interval.tick() => {}
                }
                // The ordinary scheduler retains its existing per-component logs.
                let _ = run_cleanup_pass(&state, cleanup_interval_secs).await;
            }
        },
    );
}

/// Qualified assembly replaces the ordinary scheduler with this observed entry.
/// All participating stores must belong to its selected restore domains.
pub(super) fn spawn_observed_cleanup_task(
    state: &AppState,
    dispatcher: crate::organizations::witness::deployment::dispatch::EnvironmentDispatcher,
    interval_secs: u64,
) -> anyhow::Result<super::ObservedTask> {
    anyhow::ensure!(
        dispatcher.environment_id() == state.environment_id
            && crate::config::valid_cleanup_interval_secs(interval_secs)
            && tokio::runtime::Handle::try_current().is_ok()
            && crate::organizations::request_work::async_store::task_owner()?.is_none(),
        "observed cleanup requires one Environment, a finite interval and no enclosing work"
    );
    let state = state.clone();
    let restart = state.runtime_restart.clone();
    Ok(super::owned::spawn(
        restart.clone(),
        state.runtime_authority.issuer_host().to_owned(),
        "cleanup",
        move |ready| {
            Box::pin(async move {
                let pass = move || {
                    let state = state.clone();
                    async move {
                        run_cleanup_pass(&state, interval_secs)
                            .await
                            .map_err(|_| crate::organizations::witness::Error::Refused)
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

#[expect(
    clippy::too_many_lines,
    reason = "shared existing cleanup orchestration; task admission is handled separately"
)]
async fn run_cleanup_pass(state: &AppState, cleanup_interval_secs: u64) -> Result<(), String> {
    let cleanup_issuer = state.tokens.issuer.clone();
    let cleanup_stepup = state.protocol.stepup_store.clone();
    let cleanup_par = state.protocol.par_store.clone();
    let cleanup_upstream = state.upstream.auth_store.clone();
    let cleanup_upstream_logout_relay = state.upstream.logout_relay_store.clone();
    let cleanup_discovery = state.upstream.discovery_cache.clone();
    let cleanup_jwks = state.upstream.jwks_cache.clone();
    let cleanup_device = state.device.code_store.clone();
    let cleanup_csrf = state.device.csrf_store.clone();
    let cleanup_local_auth_csrf = state.device.local_auth_csrf_store.clone();
    let cleanup_auth_sessions = state.browser_auth.auth_sessions.clone();
    let cleanup_local_login_rate_limiter = state.device.local_login_rate_limiter.clone();
    let cleanup_rate_limiter = state.device.rate_limiter.clone();
    let cleanup_management = state.management.clone();
    let cleanup_management_runtime_commands = state.db_pool.clone();
    let cleanup_authorization_pool = state.db_pool.clone();
    let cleanup_environment = state.environment_id;
    let management_runtime_command_stale_after =
        runtime_command_stale_after(cleanup_interval_secs.max(1));
    let job_timeout = cleanup_job_timeout(cleanup_interval_secs);
    let failed = AtomicBool::new(false);
    tokio::join!(
        run_async_cleanup(
            "management_sessions",
            job_timeout,
            &failed,
            cleanup_management.cleanup_sessions_async()
        ),
        run_async_cleanup(
            "stepup",
            job_timeout,
            &failed,
            cleanup_stepup.cleanup_async()
        ),
        run_async_cleanup(
            "client_assertion_replay",
            job_timeout,
            &failed,
            state.clients.cleanup_replays()
        ),
        run_async_cleanup(
            "jwks_admission",
            job_timeout,
            &failed,
            state.clients.cleanup_jwks()
        ),
        run_async_cleanup(
            "dpop_replay",
            job_timeout,
            &failed,
            state.dpop.cleanup_replays()
        ),
        async {
            match tokio::time::timeout(
                job_timeout,
                crate::lti::store::cleanup_expired(
                    &cleanup_authorization_pool,
                    cleanup_environment,
                ),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    failed.store(true, Ordering::Relaxed);
                    log_cleanup_failure("lti_launches", error);
                }
                Err(error) => {
                    failed.store(true, Ordering::Relaxed);
                    log_cleanup_failure("lti_launches", error);
                }
            }
        },
        async {
            match tokio::time::timeout(
                job_timeout,
                crate::web::cleanup_expired_authorization_transactions(
                    &cleanup_authorization_pool,
                    cleanup_environment,
                ),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    failed.store(true, Ordering::Relaxed);
                    log_cleanup_failure("authorization_transactions", error);
                }
                Err(error) => {
                    failed.store(true, Ordering::Relaxed);
                    log_cleanup_failure("authorization_transactions", error);
                }
            }
        },
        run_async_cleanup(
            "token_issuer",
            job_timeout,
            &failed,
            cleanup_issuer.cleanup_async()
        ),
        run_async_cleanup("par", job_timeout, &failed, async {
            cleanup_par
                .clone()
                .cleanup_async()
                .await
                .map_err(|error| error.error)
        }),
        run_async_cleanup(
            "upstream_auth",
            job_timeout,
            &failed,
            cleanup_upstream.cleanup_async()
        ),
        run_async_cleanup(
            "upstream_logout_relay",
            job_timeout,
            &failed,
            cleanup_upstream_logout_relay.cleanup_async()
        ),
        run_cleanup_blocking("upstream_discovery_cache", job_timeout, &failed, {
            let cleanup_discovery = cleanup_discovery.clone();
            move || cleanup_discovery.try_cleanup_expired()
        }),
        run_cleanup_blocking("upstream_jwks_cache", job_timeout, &failed, {
            let cleanup_jwks = cleanup_jwks.clone();
            move || cleanup_jwks.try_cleanup_expired()
        }),
        run_async_cleanup(
            "device_code",
            job_timeout,
            &failed,
            cleanup_device.cleanup_async()
        ),
        run_async_cleanup("device_csrf", job_timeout, &failed, async {
            cleanup_csrf
                .cleanup_async()
                .await
                .map_err(|err| err.to_string())
        }),
        run_async_cleanup("local_auth_csrf", job_timeout, &failed, async {
            cleanup_local_auth_csrf
                .cleanup_async()
                .await
                .map_err(|err| err.to_string())
        }),
        run_async_cleanup(
            "auth_sessions",
            job_timeout,
            &failed,
            cleanup_auth_sessions.cleanup_async()
        ),
        run_async_cleanup(
            "local_login_rate_limiter",
            job_timeout,
            &failed,
            cleanup_local_login_rate_limiter.clone().cleanup_async()
        ),
        run_async_cleanup(
            "device_rate_limiter",
            job_timeout,
            &failed,
            cleanup_rate_limiter.clone().cleanup_async()
        ),
        run_async_cleanup(
            "management_login_rate_limiter",
            job_timeout,
            &failed,
            cleanup_management.cleanup_login_rate_limiter_async()
        ),
        async {
            match reconcile_stale_management_runtime_commands(
                cleanup_management_runtime_commands.clone(),
                cleanup_environment,
                management_runtime_command_stale_after,
            )
            .await
            {
                Ok(0) => {}
                Ok(reconciled) => tracing::warn!(
                    target: "cleanup",
                    reconciled,
                    stale_after_secs = management_runtime_command_stale_after.as_secs(),
                    "stale management runtime commands reconciled as failed_unconfirmed"
                ),
                Err(error) => {
                    failed.store(true, Ordering::Relaxed);
                    log_cleanup_failure("management_runtime_commands", error);
                }
            }
        },
    );
    match read_authorization_code_counters(cleanup_issuer.clone()).await {
        Ok(Ok((states, nonces))) => {
            tracing::debug!(
                target: "cleanup",
                states,
                nonces,
                "periodic cleanup completed"
            );
        }
        Ok(Err(error)) => {
            failed.store(true, Ordering::Relaxed);
            tracing::warn!(
                target: "cleanup",
                error = %error,
                "periodic cleanup completed without authorization-code counters"
            );
        }
        Err(_) => {
            failed.store(true, Ordering::Relaxed);
            tracing::warn!(
                target: "cleanup",
                timeout_secs = CLEANUP_JOB_TIMEOUT_SECS,
                "periodic cleanup completed without authorization-code counters"
            );
        }
    }
    if failed.load(Ordering::Relaxed) {
        Err("one or more runtime cleanup operations failed".into())
    } else {
        Ok(())
    }
}

fn cleanup_job_timeout(cleanup_interval_secs: u64) -> Duration {
    Duration::from_secs(cleanup_interval_secs.clamp(1, CLEANUP_JOB_TIMEOUT_SECS))
}
