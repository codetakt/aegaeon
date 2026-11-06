use anyhow::{Context, Result};
use sqlx::{
    postgres::{PgConnectOptions, PgListener, PgPoolOptions},
    PgPool,
};
use std::str::FromStr;
use std::{future::Future, time::Duration};

use super::monitor::RuntimeConfigMonitor;
use crate::runtime_restart::RuntimeRestartState;

const RUNTIME_AUTHORITY_NOTIFICATION_CHANNEL: &str = "aegaeon_runtime_authority_changed";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) async fn run_runtime_authority_notification_listener(
    database_url: String,
    monitor: RuntimeConfigMonitor,
) {
    let restart = monitor.runtime_restart().clone();
    let issuer_host = monitor.issuer_host().to_owned();
    let result = run(&database_url, &issuer_host, &restart, move || {
        let monitor = monitor.clone();
        async move {
            monitor.check_revision().await;
            Ok(())
        }
    })
    .await;
    if let Err(error) = result {
        tracing::error!(target: "runtime_config_notifications", error = %error,
            "runtime notification checks stopped; requesting graceful restart");
    }
}

/// LISTEN is only a wakeup hint. Every authoritative check, including the one
/// after reconnect, must use the caller's complete finite work boundary.
pub(super) async fn run<F, Fut>(
    database_url: &str,
    issuer_host: &str,
    restart: &RuntimeRestartState,
    check: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    run_with_options(
        PgConnectOptions::from_str(database_url)?,
        issuer_host,
        restart,
        check,
    )
    .await
}

pub(super) async fn run_with_options<F, Fut>(
    options: PgConnectOptions,
    issuer_host: &str,
    restart: &RuntimeRestartState,
    check: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .connect_lazy_with(options);
    let result = run_pool(&pool, issuer_host, restart, check).await;
    tokio::time::timeout(CONNECT_TIMEOUT, pool.close())
        .await
        .context("notification hint connection cleanup incomplete")?;
    result
}

async fn run_pool<F, Fut>(
    pool: &PgPool,
    issuer_host: &str,
    restart: &RuntimeRestartState,
    mut check: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    loop {
        let Some(mut listener) = reconnect(pool, issuer_host, restart).await else {
            return Ok(());
        };
        if restart.is_requested() {
            return Ok(());
        }
        // Do not select cancellation against active work: its return includes
        // actual connection cleanup. Failure never retries an unowned check.
        check().await?;
        loop {
            tokio::select! {
                biased;
                () = restart.notified() => return Ok(()),
                notification = listener.try_recv() => {
                    match notification {
                        Ok(Some(notification)) => {
                            if !restart.is_requested()
                                && notification_matches_issuer(notification.payload(), issuer_host)
                            {
                                check().await?;
                            }
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        }
        // Discard this hint connection. Reconnect always performs a fresh check;
        // SQLx's implicit reconnect must not hide a missed notification interval.
    }
}

fn notification_matches_issuer(payload: &str, issuer_host: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return true;
    };
    let Some(hosts) = value
        .get("issuerHosts")
        .and_then(serde_json::Value::as_array)
    else {
        return true;
    };
    hosts
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|host| host.trim().eq_ignore_ascii_case(issuer_host.trim()))
}

async fn connect(pool: &PgPool) -> Result<PgListener> {
    let mut listener = PgListener::connect_with(pool)
        .await
        .context("failed to connect PostgreSQL runtime authority notification listener")?;
    listener.eager_reconnect(false);
    listener
        .listen(RUNTIME_AUTHORITY_NOTIFICATION_CHANNEL)
        .await
        .context("failed to register PostgreSQL runtime authority notification listener")?;
    Ok(listener)
}

async fn reconnect(
    pool: &PgPool,
    issuer_host: &str,
    restart: &RuntimeRestartState,
) -> Option<PgListener> {
    let mut backoff = Duration::from_secs(1);
    loop {
        let connection = tokio::select! {
            biased;
            () = restart.notified() => return None,
            result = tokio::time::timeout(CONNECT_TIMEOUT, connect(pool)) => result,
        };
        if let Ok(Ok(listener)) = connection {
            return Some(listener);
        }
        // Never log the connection URL, credential-bearing driver error or
        // untrusted payload. The periodic authority monitor remains mandatory.
        tracing::warn!(target: "runtime_config_notifications", issuer_host,
            backoff_ms = backoff.as_millis(), "notification hint connection unavailable");
        tokio::select! {
            biased;
            () = restart.notified() => return None,
            () = tokio::time::sleep(backoff) => backoff = next_reconnect_backoff(backoff),
        }
    }
}

fn next_reconnect_backoff(current: Duration) -> Duration {
    Duration::from_secs(current.as_secs().saturating_mul(2).clamp(1, 30))
}

#[cfg(test)]
mod tests {
    use super::{next_reconnect_backoff, notification_matches_issuer};
    use std::time::Duration;

    #[test]
    fn notification_matching_checks_issuer_hosts_when_present() {
        assert!(notification_matches_issuer(
            r#"{"issuerHosts":["other.example","AUTH.example"]}"#,
            "auth.example",
        ));
        assert!(!notification_matches_issuer(
            r#"{"issuerHosts":["other.example"]}"#,
            "auth.example",
        ));
        assert!(!notification_matches_issuer(
            r#"{"issuerHosts":[]}"#,
            "auth.example",
        ));
    }

    #[test]
    fn notification_matching_falls_back_to_relevant_for_unknown_payloads() {
        assert!(notification_matches_issuer("not-json", "auth.example"));
        assert!(notification_matches_issuer(
            r#"{"table":"clients"}"#,
            "auth.example",
        ));
    }

    #[test]
    fn reconnect_backoff_is_bounded() {
        assert_eq!(
            next_reconnect_backoff(Duration::from_secs(1)),
            Duration::from_secs(2)
        );
        assert_eq!(
            next_reconnect_backoff(Duration::from_secs(16)),
            Duration::from_secs(30)
        );
        assert_eq!(
            next_reconnect_backoff(Duration::from_secs(30)),
            Duration::from_secs(30)
        );
    }
}
