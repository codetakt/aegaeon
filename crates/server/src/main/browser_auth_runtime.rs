use std::sync::Arc;

use crate::config::RuntimeStateNamespace;
use crate::management::types::PolicyDocument;
use crate::web::AuthSessionStore;
use anyhow::Result;

pub(super) struct BrowserAuthRuntime {
    pub(super) auth_sessions: Arc<AuthSessionStore>,
}

pub(super) fn browser_auth_runtime_for_authority(
    pool: &sqlx::PgPool,
    policy: &PolicyDocument,
    runtime_state_namespace: &RuntimeStateNamespace,
) -> Result<BrowserAuthRuntime> {
    AuthSessionStore::from_postgres(policy, pool.clone(), runtime_state_namespace)
        .map(Arc::new)
        .map(|auth_sessions| BrowserAuthRuntime { auth_sessions })
        .map_err(Into::into)
}
