use super::backchannel_logout::dispatch_backchannel_logout_async;
use super::AppState;
use crate::oidc::{OidcConfig, OidcLogoutEvent};

pub(super) async fn dispatch_backchannel_logout_if_enabled(
    state: &AppState,
    cfg: &OidcConfig,
    logout_events: Vec<OidcLogoutEvent>,
) {
    if !cfg.backchannel_logout_enabled {
        return;
    }

    for event in logout_events {
        let report = dispatch_backchannel_logout_async(cfg, state.clients.as_ref(), &event).await;
        if report.has_failures() {
            tracing::warn!(
                targeted_clients = report.targeted_clients,
                delivered = report.delivered,
                skipped_unregistered_clients = report.skipped_unregistered_clients,
                skipped_without_logout_uri = report.skipped_without_logout_uri,
                rejected_logout_uri = report.rejected_logout_uri,
                token_build_failures = report.token_build_failures,
                delivery_failures = report.delivery_failures,
                http_client_init_failed = report.http_client_init_failed,
                "backchannel logout dispatch completed with failures"
            );
        } else if report.delivered > 0 {
            tracing::info!(
                targeted_clients = report.targeted_clients,
                delivered = report.delivered,
                "backchannel logout dispatch completed"
            );
        }
    }
}
