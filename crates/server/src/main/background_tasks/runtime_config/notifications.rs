use anyhow::{Context, Result};
use sqlx::postgres::{PgListener, PgNotification};
use std::time::Duration;

use super::monitor::RuntimeConfigMonitor;

const RUNTIME_AUTHORITY_NOTIFICATION_CHANNEL: &str = "aegaeon_runtime_authority_changed";

struct RuntimeAuthorityNotificationListener {
    listener: PgListener,
    database_url: String,
    monitor: RuntimeConfigMonitor,
}

impl RuntimeAuthorityNotificationListener {
    async fn run(mut self) {
        loop {
            tokio::select! {
                () = self.monitor.runtime_restart().notified() => {
                    tracing::info!(
                        target: "runtime_config_notifications",
                        issuer_host = %self.monitor.issuer_host(),
                        "runtime authority notification listener stopped after runtime restart request"
                    );
                    break;
                }
                notification = self.listener.recv() => {
                    match notification {
                        Ok(notification) => self.handle_notification(&notification).await,
                        Err(error) => {
                            tracing::warn!(
                                target: "runtime_config_notifications",
                                issuer_host = %self.monitor.issuer_host(),
                                error = %error,
                                "runtime authority notification listener failed; reconnecting while polling monitor remains authoritative"
                            );
                            let Some(listener) =
                                reconnect_runtime_authority_listener(&self.database_url, &self.monitor)
                                    .await
                            else {
                                break;
                            };
                            self.listener = listener;
                        }
                    }
                }
            }
        }
    }

    async fn handle_notification(&self, notification: &PgNotification) {
        if !notification_matches_issuer(notification.payload(), self.monitor.issuer_host()) {
            tracing::debug!(
                target: "runtime_config_notifications",
                issuer_host = %self.monitor.issuer_host(),
                channel = notification.channel(),
                payload = notification.payload(),
                "runtime authority change notification ignored for unrelated issuer"
            );
            return;
        }

        tracing::debug!(
            target: "runtime_config_notifications",
            issuer_host = %self.monitor.issuer_host(),
            channel = notification.channel(),
            payload = notification.payload(),
            "runtime authority change notification received"
        );
        self.monitor.check_revision().await;
    }
}

pub(super) async fn run_runtime_authority_notification_listener(
    database_url: String,
    monitor: RuntimeConfigMonitor,
) {
    let Some(listener) = reconnect_runtime_authority_listener(&database_url, &monitor).await else {
        return;
    };
    RuntimeAuthorityNotificationListener {
        listener,
        database_url,
        monitor,
    }
    .run()
    .await;
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

async fn connect_runtime_authority_listener(database_url: &str) -> Result<PgListener> {
    let mut listener = PgListener::connect(database_url)
        .await
        .context("failed to connect PostgreSQL runtime authority notification listener")?;
    listener
        .listen(RUNTIME_AUTHORITY_NOTIFICATION_CHANNEL)
        .await
        .context("failed to register PostgreSQL runtime authority notification listener")?;
    Ok(listener)
}

async fn reconnect_runtime_authority_listener(
    database_url: &str,
    monitor: &RuntimeConfigMonitor,
) -> Option<PgListener> {
    let mut backoff = Duration::from_secs(1);
    loop {
        if monitor.runtime_restart().is_requested() {
            return None;
        }
        match connect_runtime_authority_listener(database_url).await {
            Ok(listener) => {
                tracing::info!(
                    target: "runtime_config_notifications",
                    issuer_host = %monitor.issuer_host(),
                    "runtime authority notification listener reconnected"
                );
                monitor.check_revision().await;
                return Some(listener);
            }
            Err(error) => {
                tracing::warn!(
                    target: "runtime_config_notifications",
                    issuer_host = %monitor.issuer_host(),
                    error = %error,
                    backoff_ms = backoff.as_millis(),
                    "runtime authority notification listener reconnect failed"
                );
                tokio::select! {
                    () = monitor.runtime_restart().notified() => return None,
                    () = tokio::time::sleep(backoff) => {
                        backoff = next_reconnect_backoff(backoff);
                    }
                }
            }
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
