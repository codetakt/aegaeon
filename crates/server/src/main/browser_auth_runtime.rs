use std::sync::Arc;

use aegaeon_server::config::RuntimeStateNamespace;
use aegaeon_server::management::types::PolicyDocument;
use aegaeon_server::web::AuthSessionStore;
use anyhow::Result;

pub(super) struct BrowserAuthRuntime {
    pub(super) auth_sessions: Arc<AuthSessionStore>,
}

pub(super) fn browser_auth_runtime_for_authority(
    policy: &PolicyDocument,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<BrowserAuthRuntime> {
    AuthSessionStore::try_from_management_policy(policy, runtime_state_namespace)
        .map(Arc::new)
        .map(|auth_sessions| BrowserAuthRuntime { auth_sessions })
        .map_err(Into::into)
}
