use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

use tokio::sync::Notify;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeRestartRequest {
    request_id: Arc<str>,
    issuer_host: Arc<str>,
    reason: RuntimeRestartReason,
}

impl RuntimeRestartRequest {
    #[must_use]
    pub fn runtime_critical_mutation(
        request_id: impl Into<Arc<str>>,
        issuer_host: impl Into<Arc<str>>,
        mutation: &'static str,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            issuer_host: issuer_host.into(),
            reason: RuntimeRestartReason::RuntimeCriticalMutation { mutation },
        }
    }

    #[must_use]
    pub fn runtime_client_projection_sync_failure(
        request_id: impl Into<Arc<str>>,
        issuer_host: impl Into<Arc<str>>,
        surface: &'static str,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            issuer_host: issuer_host.into(),
            reason: RuntimeRestartReason::RuntimeClientProjectionSyncFailure { surface },
        }
    }

    #[must_use]
    pub fn runtime_authority_drift(
        request_id: impl Into<Arc<str>>,
        issuer_host: impl Into<Arc<str>>,
        surface: &'static str,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            issuer_host: issuer_host.into(),
            reason: RuntimeRestartReason::RuntimeAuthorityDrift { surface },
        }
    }

    #[must_use]
    pub fn runtime_authority_unavailable(
        request_id: impl Into<Arc<str>>,
        issuer_host: impl Into<Arc<str>>,
        surface: &'static str,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            issuer_host: issuer_host.into(),
            reason: RuntimeRestartReason::RuntimeAuthorityUnavailable { surface },
        }
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn issuer_host(&self) -> &str {
        &self.issuer_host
    }

    #[must_use]
    pub fn reason(&self) -> RuntimeRestartReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeRestartReason {
    RuntimeCriticalMutation { mutation: &'static str },
    RuntimeClientProjectionSyncFailure { surface: &'static str },
    RuntimeAuthorityDrift { surface: &'static str },
    RuntimeAuthorityUnavailable { surface: &'static str },
}

#[derive(Clone, Default)]
pub struct RuntimeRestartState {
    inner: Arc<RuntimeRestartStateInner>,
}

#[derive(Default)]
struct RuntimeRestartStateInner {
    requested: AtomicBool,
    request: RwLock<Option<RuntimeRestartRequest>>,
    notify: Notify,
}

impl RuntimeRestartState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request_restart(&self, request: RuntimeRestartRequest) {
        if self.is_requested() {
            return;
        }

        let Ok(mut stored) = self.inner.request.write() else {
            self.inner.requested.store(true, Ordering::SeqCst);
            self.inner.notify.notify_waiters();
            return;
        };
        if stored.is_some() {
            return;
        }

        *stored = Some(request);
        self.inner.requested.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.inner.requested.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn request(&self) -> Option<RuntimeRestartRequest> {
        self.inner
            .request
            .read()
            .ok()
            .and_then(|request| request.clone())
    }

    pub async fn notified(&self) {
        // notify_waiters is observed from future creation, including before its
        // first poll. Register before reading the flag to avoid a lost broadcast.
        let notified = self.inner.notify.notified();
        self.wait_for_request(notified).await;
    }

    fn wait_for_request<'a>(
        &self,
        notified: tokio::sync::futures::Notified<'a>,
    ) -> impl std::future::Future<Output = ()> + 'a {
        let requested = self.is_requested();
        async move {
            if !requested {
                notified.await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    #[test]
    fn runtime_restart_state_records_first_request_only() -> Result<(), String> {
        let state = RuntimeRestartState::new();

        state.request_restart(RuntimeRestartRequest::runtime_critical_mutation(
            "req-1".to_string(),
            "auth.example.com".to_string(),
            "configuration_version_activate",
        ));
        state.request_restart(
            RuntimeRestartRequest::runtime_client_projection_sync_failure(
                "req-2".to_string(),
                "auth.example.com".to_string(),
                "dcr_database_registry",
            ),
        );

        let request = state
            .request()
            .ok_or_else(|| "restart request should be recorded".to_string())?;
        assert_eq!(request.request_id(), "req-1");
        assert_eq!(request.issuer_host(), "auth.example.com");
        assert_eq!(
            request.reason(),
            RuntimeRestartReason::RuntimeCriticalMutation {
                mutation: "configuration_version_activate"
            }
        );
        Ok(())
    }

    #[test]
    fn runtime_restart_request_records_runtime_authority_reasons() {
        let drift = RuntimeRestartRequest::runtime_authority_drift(
            "req-drift",
            "auth.example.com",
            "runtime_config_monitor",
        );
        assert_eq!(drift.request_id(), "req-drift");
        assert_eq!(drift.issuer_host(), "auth.example.com");
        assert_eq!(
            drift.reason(),
            RuntimeRestartReason::RuntimeAuthorityDrift {
                surface: "runtime_config_monitor"
            }
        );

        let unavailable = RuntimeRestartRequest::runtime_authority_unavailable(
            "req-unavailable",
            "auth.example.com",
            "runtime_authority_guard",
        );
        assert_eq!(unavailable.request_id(), "req-unavailable");
        assert_eq!(unavailable.issuer_host(), "auth.example.com");
        assert_eq!(
            unavailable.reason(),
            RuntimeRestartReason::RuntimeAuthorityUnavailable {
                surface: "runtime_authority_guard"
            }
        );
    }

    #[tokio::test]
    async fn runtime_restart_notification_returns_after_request() {
        let state = RuntimeRestartState::new();
        state.request_restart(RuntimeRestartRequest::runtime_critical_mutation(
            "req-1".to_string(),
            "auth.example.com".to_string(),
            "configuration_version_activate",
        ));

        state.notified().await;
    }

    #[tokio::test]
    async fn runtime_restart_notification_covers_unpolled_broadcast_interleavings() {
        for before_flag in [true, false] {
            let state = RuntimeRestartState::new();
            let notified = state.inner.notify.notified();
            let request = || {
                state.request_restart(RuntimeRestartRequest::runtime_authority_drift(
                    "first",
                    "auth.example.com",
                    "test",
                ));
            };
            if before_flag {
                request();
            }
            let pending = state.wait_for_request(notified);
            if !before_flag {
                request();
            }
            tokio::time::timeout(std::time::Duration::from_secs(1), pending)
                .await
                .expect("broadcast between registration/flag/poll must not be lost");
            state.notified().await;
            state.notified().await;
        }
    }

    #[tokio::test]
    async fn runtime_restart_notification_broadcasts_to_all_waiters() {
        let state = RuntimeRestartState::new();
        let waiters: Vec<_> = (0..8).map(|_| Box::pin(state.notified())).collect();
        let mut waiters = waiters;
        for waiter in &mut waiters {
            let poll =
                std::future::poll_fn(|cx| std::task::Poll::Ready(waiter.as_mut().poll(cx))).await;
            assert!(poll.is_pending());
        }
        state.request_restart(RuntimeRestartRequest::runtime_authority_drift(
            "first",
            "auth.example.com",
            "test",
        ));
        state.request_restart(RuntimeRestartRequest::runtime_authority_drift(
            "later",
            "auth.example.com",
            "ignored",
        ));
        for waiter in waiters {
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .expect("every registered waiter must wake");
        }
        assert_eq!(state.request().unwrap().request_id(), "first");
    }
}
