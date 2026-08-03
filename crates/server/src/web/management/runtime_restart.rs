use crate::runtime_restart::{RuntimeRestartRequest, RuntimeRestartState};

use super::AppState;

#[derive(Clone)]
pub(in crate::web::management) struct RuntimeCriticalMutationGuard {
    current_issuer_host: String,
    runtime_restart: RuntimeRestartState,
}

impl RuntimeCriticalMutationGuard {
    pub(in crate::web::management) fn from_state(state: &AppState) -> Self {
        Self {
            current_issuer_host: state.runtime_authority.issuer_host().to_string(),
            runtime_restart: state.runtime_restart.clone(),
        }
    }

    pub(in crate::web::management) fn request_restart_if_current_issuer_was_mutated(
        &self,
        issuer_host: &str,
        request_id: &str,
        mutation: &'static str,
    ) {
        if self.current_issuer_matches(issuer_host) {
            self.request_restart_after_committed_runtime_critical_mutation(
                request_id,
                issuer_host,
                mutation,
            );
        }
    }

    fn current_issuer_matches(&self, issuer_host: &str) -> bool {
        let current = self.current_issuer_host.trim();
        let target = issuer_host.trim();

        !current.is_empty() && !target.is_empty() && current.eq_ignore_ascii_case(target)
    }

    fn request_restart_after_committed_runtime_critical_mutation(
        &self,
        request_id: &str,
        issuer_host: &str,
        mutation: &'static str,
    ) {
        tracing::error!(
            target: "management_runtime_critical_mutation",
            request_id,
            issuer_host,
            mutation,
            database_committed = true,
            "runtime-critical management mutation committed for current issuer; requesting graceful restart before serving the new runtime state"
        );
        self.runtime_restart
            .request_restart(RuntimeRestartRequest::runtime_critical_mutation(
                request_id.to_string(),
                issuer_host.to_string(),
                mutation,
            ));
    }
}
