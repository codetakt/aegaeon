use std::sync::Arc;
use std::time::Duration;

use aegaeon_server::management::runtime_commands::{
    reconcile_stale_management_user_runtime_commands, runtime_command_stale_after,
};
use aegaeon_server::web::AppState;
use sqlx::PgPool;

const CLEANUP_JOB_TIMEOUT_SECS: u64 = 30;

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
    cleanup: impl FnOnce() -> Result<(), String> + Send + 'static,
) {
    match tokio::time::timeout(timeout, tokio::task::spawn_blocking(cleanup)).await {
        Ok(Ok(Ok(()))) => {}
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
}

async fn read_authorization_code_counters_blocking(
    issuer: Arc<aegaeon_server::authcode::TokenIssuer>,
) -> Result<
    Result<(Result<usize, String>, Result<usize, String>), tokio::task::JoinError>,
    tokio::time::error::Elapsed,
> {
    tokio::time::timeout(
        Duration::from_secs(CLEANUP_JOB_TIMEOUT_SECS),
        tokio::task::spawn_blocking(move || (issuer.try_state_count(), issuer.try_nonce_count())),
    )
    .await
}

async fn reconcile_stale_management_runtime_commands(
    pool: PgPool,
    stale_after: Duration,
) -> Result<u64, String> {
    reconcile_stale_management_user_runtime_commands(&pool, stale_after)
        .await
        .map_err(|err| err.to_string())
}

#[expect(
    clippy::too_many_lines,
    reason = "existing cleanup scheduler orchestration; new oversized functions remain gated"
)]
pub(super) fn spawn_cleanup_task(state: &AppState, cleanup_interval_secs: u64) {
    let cleanup_issuer = state.tokens.issuer.clone();
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
    let management_runtime_command_stale_after =
        runtime_command_stale_after(cleanup_interval_secs.max(1));
    let runtime_restart = state.runtime_restart.clone();
    let issuer_host = state.runtime_authority.issuer_host().to_string();
    let supervisor_runtime_restart = runtime_restart.clone();

    super::spawn_supervised_runtime_task(
        supervisor_runtime_restart,
        issuer_host,
        super::CLEANUP_TASK_REQUEST_ID,
        "cleanup",
        async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(cleanup_interval_secs.max(1)));
            let job_timeout = cleanup_job_timeout(cleanup_interval_secs);
            loop {
                tokio::select! {
                    () = runtime_restart.notified() => {
                        tracing::info!(target: "cleanup", "periodic cleanup stopped after runtime restart request");
                        break;
                    }
                    _ = interval.tick() => {}
                }
                tokio::join!(
                    run_cleanup_blocking("token_issuer", job_timeout, {
                        let cleanup_issuer = cleanup_issuer.clone();
                        move || cleanup_issuer.try_cleanup_expired()
                    }),
                    run_cleanup_blocking("par", job_timeout, {
                        let cleanup_par = cleanup_par.clone();
                        move || {
                            cleanup_par.try_cleanup_expired().map_err(|err| {
                                let description = err
                                    .error_description
                                    .as_deref()
                                    .map_or(String::new(), |description| {
                                        format!(": {description}")
                                    });
                                format!("{}{description}", err.error)
                            })
                        }
                    }),
                    run_cleanup_blocking("upstream_auth", job_timeout, {
                        let cleanup_upstream = cleanup_upstream.clone();
                        move || cleanup_upstream.try_cleanup_expired()
                    }),
                    run_cleanup_blocking("upstream_logout_relay", job_timeout, {
                        let cleanup_upstream_logout_relay = cleanup_upstream_logout_relay.clone();
                        move || cleanup_upstream_logout_relay.try_cleanup_expired()
                    }),
                    run_cleanup_blocking("upstream_discovery_cache", job_timeout, {
                        let cleanup_discovery = cleanup_discovery.clone();
                        move || cleanup_discovery.try_cleanup_expired()
                    }),
                    run_cleanup_blocking("upstream_jwks_cache", job_timeout, {
                        let cleanup_jwks = cleanup_jwks.clone();
                        move || cleanup_jwks.try_cleanup_expired()
                    }),
                    run_cleanup_blocking("device_code", job_timeout, {
                        let cleanup_device = cleanup_device.clone();
                        move || cleanup_device.try_cleanup_expired()
                    }),
                    run_cleanup_blocking("device_csrf", job_timeout, {
                        let cleanup_csrf = cleanup_csrf.clone();
                        move || {
                            cleanup_csrf
                                .try_cleanup_expired()
                                .map_err(|err| err.to_string())
                        }
                    }),
                    run_cleanup_blocking("local_auth_csrf", job_timeout, {
                        let cleanup_local_auth_csrf = cleanup_local_auth_csrf.clone();
                        move || {
                            cleanup_local_auth_csrf
                                .try_cleanup_expired()
                                .map_err(|err| err.to_string())
                        }
                    }),
                    run_cleanup_blocking("auth_sessions", job_timeout, {
                        let cleanup_auth_sessions = cleanup_auth_sessions.clone();
                        move || {
                            cleanup_auth_sessions
                                .try_cleanup_expired()
                                .map(|_removed| ())
                        }
                    }),
                    run_cleanup_blocking("local_login_rate_limiter", job_timeout, {
                        let cleanup_local_login_rate_limiter =
                            cleanup_local_login_rate_limiter.clone();
                        move || cleanup_local_login_rate_limiter.try_cleanup_expired()
                    }),
                    run_cleanup_blocking("device_rate_limiter", job_timeout, {
                        let cleanup_rate_limiter = cleanup_rate_limiter.clone();
                        move || cleanup_rate_limiter.try_cleanup_expired()
                    }),
                    run_cleanup_blocking("management_login_rate_limiter", job_timeout, {
                        let cleanup_management = cleanup_management.clone();
                        move || cleanup_management.try_cleanup_login_rate_limiter()
                    }),
                    async {
                        match reconcile_stale_management_runtime_commands(
                            cleanup_management_runtime_commands.clone(),
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
                            Err(error) => log_cleanup_failure("management_runtime_commands", error),
                        }
                    },
                );
                match read_authorization_code_counters_blocking(cleanup_issuer.clone()).await {
                    Ok(Ok((Ok(states), Ok(nonces)))) => {
                        tracing::debug!(
                            target: "cleanup",
                            states,
                            nonces,
                            "periodic cleanup completed"
                        );
                    }
                    Ok(Ok((state_result, nonce_result))) => {
                        tracing::warn!(
                            target: "cleanup",
                            state_count_error = state_result.as_ref().err().map_or("", String::as_str),
                            nonce_count_error = nonce_result.as_ref().err().map_or("", String::as_str),
                            "periodic cleanup completed without authorization-code counters"
                        );
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(
                            target: "cleanup",
                            error = %error,
                            "periodic cleanup completed without authorization-code counters"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            target: "cleanup",
                            timeout_secs = CLEANUP_JOB_TIMEOUT_SECS,
                            "periodic cleanup completed without authorization-code counters"
                        );
                    }
                }
            }
        },
    );
}

fn cleanup_job_timeout(cleanup_interval_secs: u64) -> Duration {
    Duration::from_secs(cleanup_interval_secs.clamp(1, CLEANUP_JOB_TIMEOUT_SECS))
}
