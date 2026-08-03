use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

use crate::runtime_restart::RuntimeRestartRequest;
use crate::web::management::{error_response, management_internal_error};

use super::RuntimeClientMutationSync;

fn request_restart_after_committed_runtime_client_sync_failure(
    runtime_restart: &crate::runtime_restart::RuntimeRestartState,
    request_id: &str,
    issuer_host: &str,
    error: &crate::runtime_authority::RuntimeClientProjectionSyncError,
) {
    tracing::error!(
        target: "management_runtime_client_sync",
        request_id,
        issuer_host,
        database_committed = true,
        error = %error,
        "runtime client snapshot synchronization after management mutation failed; requesting graceful restart before serving stale client state"
    );
    runtime_restart.request_restart(
        RuntimeRestartRequest::runtime_client_projection_sync_failure(
            request_id.to_string(),
            issuer_host.to_string(),
            "management_runtime_client_sync",
        ),
    );
}

fn committed_runtime_client_sync_failure_response(request_id: &str) -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "Runtime client projection synchronization failed after database commit",
        None,
        Some(request_id),
    )
}

impl<'a> RuntimeClientMutationSync<'a> {
    pub(in crate::web::management) fn database_issuer_host_for_snapshot_sync(
        self,
        request_id: &str,
    ) -> Result<&'a str, Response> {
        let issuer_host = self.runtime_authority.issuer_host().trim();
        if issuer_host.is_empty() {
            tracing::error!(
                target: "management_runtime_client_sync",
                request_id,
                "database runtime client synchronization is enabled without an issuer host"
            );
            return Err(management_internal_error(
                request_id,
                "Runtime issuer host is not configured",
            ));
        }
        Ok(issuer_host)
    }

    pub(in crate::web::management::runtime_clients) async fn replace_current_issuer_snapshot(
        self,
        pool: &PgPool,
        request_id: &str,
    ) -> Result<(), Response> {
        let issuer_host = self.database_issuer_host_for_snapshot_sync(request_id)?;
        match self
            .runtime_authority
            .try_synchronize_client_projection_from_database(pool, self.clients)
            .await
        {
            Ok(synchronized) => {
                let synchronized_client_count = synchronized.synchronized_client_count();
                tracing::debug!(
                    target: "management_runtime_client_sync",
                    request_id,
                    issuer_host,
                    count = synchronized_client_count,
                    "runtime client snapshot synchronized after management mutation"
                );
                Ok(())
            }
            Err(error) => {
                request_restart_after_committed_runtime_client_sync_failure(
                    self.runtime_restart,
                    request_id,
                    issuer_host,
                    &error,
                );
                Err(committed_runtime_client_sync_failure_response(request_id))
            }
        }
    }
}
