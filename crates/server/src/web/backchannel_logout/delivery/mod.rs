use super::*;
use crate::oidc::session::delivery::{
    Binding, Candidate, Command, Completion, Identity, Outcome, Permit, Request,
};
use crate::oidc::OidcSessionStore;
use std::sync::Arc;
use std::time::Duration;

mod http;
mod recipient;

#[derive(Clone, Copy, Default)]
pub(super) struct Clock {
    #[cfg(test)]
    pub fixed: Option<SystemTime>,
}
impl Clock {
    fn now(self) -> SystemTime {
        #[cfg(test)]
        {
            self.fixed.unwrap_or_else(SystemTime::now)
        }
        #[cfg(not(test))]
        {
            SystemTime::now()
        }
    }
    fn request(
        self,
        identity: Identity,
        binding: Option<Binding>,
        command: Command,
    ) -> Result<Request, String> {
        let request = Request::new(identity, binding, command);
        #[cfg(test)]
        {
            let mut request = request;
            request.test_now = self
                .fixed
                .map(|time| time.duration_since(UNIX_EPOCH).map(|n| n.as_secs()))
                .transpose()
                .map_err(|_| "invalid logout delivery clock".to_string())?;
            Ok(request)
        }
        #[cfg(not(test))]
        {
            Ok(request)
        }
    }
}

pub(in crate::web) async fn dispatch_backchannel_logout_async(
    cfg: &OidcConfig,
    clients: &ClientRegistry,
    sessions: Option<&OidcSessionStore>,
    event: &OidcLogoutEvent,
) -> BackchannelLogoutDispatchReport {
    dispatch_at(cfg, clients, sessions, event, Clock::default()).await
}

pub(super) async fn dispatch_at(
    cfg: &OidcConfig,
    clients: &ClientRegistry,
    sessions: Option<&OidcSessionStore>,
    event: &OidcLogoutEvent,
    clock: Clock,
) -> BackchannelLogoutDispatchReport {
    let mut report = BackchannelLogoutDispatchReport::for_event(event);
    if !cfg.backchannel_logout_enabled {
        report.disabled_clients = event.client_ids.len();
        return report;
    }
    let Some(sessions) = sessions else {
        report.storage_failures = event.client_ids.len();
        return report;
    };
    let http = match http::client() {
        Ok(client) => client,
        Err(_) => {
            report.http_client_init_failed = true;
            return report;
        }
    };
    let context = recipient::Context {
        cfg,
        clients,
        sessions,
        http: &http,
        clock,
        event,
    };
    for client_id in &event.client_ids {
        if context.dispatch(client_id, &mut report).await.is_err() {
            report.storage_failures += 1;
        }
    }
    report
}

#[cfg(test)]
pub(in crate::web) fn dispatch_backchannel_logout(
    cfg: &OidcConfig,
    clients: &ClientRegistry,
    sessions: Option<&OidcSessionStore>,
    event: &OidcLogoutEvent,
) -> BackchannelLogoutDispatchReport {
    // Both test entry points use the production ownership protocol, including inside an existing runtime.
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map(|runtime| {
                        runtime.block_on(dispatch_backchannel_logout_async(
                            cfg, clients, sessions, event,
                        ))
                    })
                    .unwrap_or_else(|_| BackchannelLogoutDispatchReport {
                        http_client_init_failed: true,
                        ..BackchannelLogoutDispatchReport::for_event(event)
                    })
            })
            .join()
            .unwrap_or_else(|_| BackchannelLogoutDispatchReport {
                storage_failures: event.client_ids.len(),
                ..BackchannelLogoutDispatchReport::for_event(event)
            })
    })
}

fn record_outcome(outcome: &Outcome, report: &mut BackchannelLogoutDispatchReport) {
    match outcome {
        Outcome::AlreadyDelivered => report.already_delivered += 1,
        Outcome::Deferred | Outcome::Ready { .. } => report.deferred += 1,
        Outcome::Terminal => report.terminal_undelivered += 1,
        Outcome::LegacyUnknown | Outcome::Missing => report.legacy_unknown += 1,
        Outcome::Granted(_) | Outcome::Completed => report.storage_failures += 1,
    }
}
