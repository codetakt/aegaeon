use aegaeon_server::client_registry::ClientRegistry;
use aegaeon_server::runtime_authority::RuntimeAuthorityState;
use aegaeon_server::runtime_configuration::{
    load_active_runtime_configuration_revision_for_issuer_host, DatabaseRuntimeConfiguration,
    RuntimeAuthorityRevision,
};
use aegaeon_server::runtime_restart::{RuntimeRestartRequest, RuntimeRestartState};
use aegaeon_server::web::AppState;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

use super::RUNTIME_CONFIG_MONITOR_REQUEST_ID;

#[derive(Clone)]
pub(super) struct RuntimeConfigMonitor {
    pool: PgPool,
    issuer_host: String,
    runtime_authority: RuntimeAuthorityState,
    runtime_restart: RuntimeRestartState,
    clients: Arc<ClientRegistry>,
}

impl RuntimeConfigMonitor {
    pub(super) fn from_state(
        state: &AppState,
        runtime_config: &DatabaseRuntimeConfiguration,
    ) -> Self {
        Self {
            pool: state.db_pool.clone(),
            issuer_host: runtime_config.issuer_host.clone(),
            runtime_authority: state.runtime_authority.clone(),
            runtime_restart: state.runtime_restart.clone(),
            clients: state.clients.clone(),
        }
    }

    pub(super) fn issuer_host(&self) -> &str {
        &self.issuer_host
    }

    pub(super) fn runtime_restart(&self) -> &RuntimeRestartState {
        &self.runtime_restart
    }

    pub(super) async fn run(self, interval_secs: u64) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        interval.tick().await;
        loop {
            tokio::select! {
                () = self.runtime_restart.notified() => {
                    tracing::info!(
                        target: "runtime_config_monitor",
                        issuer_host = %self.issuer_host,
                        "runtime configuration monitor stopped after runtime restart request"
                    );
                    break;
                }
                _ = interval.tick() => self.check_revision().await,
            }
        }
    }

    pub(super) async fn check_revision(&self) {
        if self.runtime_restart.is_requested() {
            return;
        }

        let Some(loaded_revision) = self.loaded_revision_or_request_restart() else {
            return;
        };
        match load_active_runtime_configuration_revision_for_issuer_host(
            &self.pool,
            &self.issuer_host,
        )
        .await
        {
            Ok(revision) if loaded_revision.stable_authority_matches(&revision) => {
                self.check_runtime_client_revision(&loaded_revision, &revision)
                    .await;
            }
            Ok(revision) => {
                self.request_restart_on_policy_or_key_change(&loaded_revision, &revision);
            }
            Err(error) => {
                tracing::error!(
                    target: "runtime_config_monitor",
                    issuer_host = %self.issuer_host,
                    loaded_configuration_version_id = %loaded_revision.active_configuration_version_id(),
                    error = %error,
                    "runtime configuration monitor failed; requesting graceful restart to avoid serving stale policy"
                );
                self.runtime_restart.request_restart(
                    RuntimeRestartRequest::runtime_authority_unavailable(
                        RUNTIME_CONFIG_MONITOR_REQUEST_ID,
                        self.issuer_host.clone(),
                        "runtime_config_monitor",
                    ),
                );
            }
        }
    }

    fn loaded_revision_or_request_restart(&self) -> Option<RuntimeAuthorityRevision> {
        match self.runtime_authority.revision() {
            Ok(revision) => Some(revision),
            Err(error) => {
                tracing::error!(
                    target: "runtime_config_monitor",
                    issuer_host = %self.issuer_host,
                    error = %error,
                    "runtime authority revision unavailable; requesting graceful restart to avoid serving stale runtime state"
                );
                self.runtime_restart.request_restart(
                    RuntimeRestartRequest::runtime_authority_unavailable(
                        RUNTIME_CONFIG_MONITOR_REQUEST_ID,
                        self.issuer_host.clone(),
                        "runtime_config_monitor",
                    ),
                );
                None
            }
        }
    }

    async fn check_runtime_client_revision(
        &self,
        loaded_revision: &RuntimeAuthorityRevision,
        revision: &RuntimeAuthorityRevision,
    ) {
        let runtime_snapshot_fingerprint = match self.clients.try_runtime_snapshot_fingerprint() {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                tracing::error!(
                    target: "runtime_config_monitor",
                    issuer_host = %self.issuer_host,
                    configuration_version_id = %loaded_revision.active_configuration_version_id(),
                    error = %error,
                    "runtime client snapshot fingerprint unavailable; requesting graceful restart to avoid serving stale client state"
                );
                self.runtime_restart.request_restart(
                    RuntimeRestartRequest::runtime_authority_unavailable(
                        RUNTIME_CONFIG_MONITOR_REQUEST_ID,
                        self.issuer_host.clone(),
                        "runtime_config_monitor",
                    ),
                );
                return;
            }
        };
        if runtime_snapshot_fingerprint.as_deref()
            == Some(revision.active_runtime_client_fingerprint())
        {
            self.advance_runtime_authority_revision_or_request_restart(
                loaded_revision,
                revision.clone(),
            );
            tracing::debug!(
                target: "runtime_config_monitor",
                issuer_host = %self.issuer_host,
                configuration_version_id = %loaded_revision.active_configuration_version_id(),
                "runtime configuration revision unchanged"
            );
        } else {
            self.sync_runtime_clients_or_request_restart(loaded_revision)
                .await;
        }
    }

    async fn sync_runtime_clients_or_request_restart(
        &self,
        loaded_revision: &RuntimeAuthorityRevision,
    ) {
        tracing::warn!(
            target: "runtime_config_monitor",
            issuer_host = %self.issuer_host,
            configuration_version_id = %loaded_revision.active_configuration_version_id(),
            "runtime client projection changed; synchronizing issuer-scoped client snapshot"
        );
        match self
            .runtime_authority
            .try_synchronize_client_projection_from_database_from(
                &self.pool,
                loaded_revision,
                self.clients.as_ref(),
            )
            .await
        {
            Ok(synchronized) => {
                tracing::debug!(
                    target: "runtime_config_monitor",
                    issuer_host = %self.issuer_host,
                    count = synchronized.synchronized_client_count(),
                    "runtime client projection synchronized"
                );
            }
            Err(error) => {
                tracing::error!(
                    target: "runtime_config_monitor",
                    issuer_host = %self.issuer_host,
                    configuration_version_id = %loaded_revision.active_configuration_version_id(),
                    error = %error,
                    "runtime client projection changed but synchronization failed; requesting graceful restart to avoid serving stale client state"
                );
                self.runtime_restart.request_restart(
                    RuntimeRestartRequest::runtime_client_projection_sync_failure(
                        RUNTIME_CONFIG_MONITOR_REQUEST_ID,
                        self.issuer_host.clone(),
                        "runtime_config_monitor",
                    ),
                );
            }
        }
    }

    fn advance_runtime_authority_revision_or_request_restart(
        &self,
        expected_revision: &RuntimeAuthorityRevision,
        revision: RuntimeAuthorityRevision,
    ) {
        if let Err(error) = self
            .runtime_authority
            .try_advance_client_projection_revision_from(expected_revision, revision)
        {
            tracing::error!(
                target: "runtime_config_monitor",
                issuer_host = %self.issuer_host,
                error = %error,
                "runtime authority revision update failed during runtime configuration monitoring; requesting graceful restart to avoid serving stale client state"
            );
            self.runtime_restart.request_restart(
                RuntimeRestartRequest::runtime_authority_unavailable(
                    RUNTIME_CONFIG_MONITOR_REQUEST_ID,
                    self.issuer_host.clone(),
                    "runtime_config_monitor",
                ),
            );
        }
    }

    fn request_restart_on_policy_or_key_change(
        &self,
        loaded_revision: &RuntimeAuthorityRevision,
        revision: &RuntimeAuthorityRevision,
    ) {
        tracing::error!(
            target: "runtime_config_monitor",
            issuer_host = %self.issuer_host,
            loaded_configuration_version_id = %loaded_revision.active_configuration_version_id(),
            active_configuration_version_id = %revision.active_configuration_version_id(),
            configuration_document_changed = revision.active_configuration_document_fingerprint() != loaded_revision.active_configuration_document_fingerprint(),
            runtime_key_set_changed = revision.active_runtime_key_set_fingerprint() != loaded_revision.active_runtime_key_set_fingerprint(),
            dcr_bearer_token_changed = revision.active_dcr_bearer_token_fingerprint() != loaded_revision.active_dcr_bearer_token_fingerprint(),
            "management database runtime configuration changed; requesting graceful restart to avoid serving stale policy or key material"
        );
        self.runtime_restart
            .request_restart(RuntimeRestartRequest::runtime_authority_drift(
                RUNTIME_CONFIG_MONITOR_REQUEST_ID,
                self.issuer_host.clone(),
                "runtime_config_monitor",
            ));
    }
}
