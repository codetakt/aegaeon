use std::sync::Arc;

use crate::config::RuntimeStateNamespace;

#[derive(Clone)]
pub(in crate::web::management) struct RedisManagementSessionKeyspace {
    pub(in crate::web::management) prefix: Arc<str>,
}

impl RedisManagementSessionKeyspace {
    pub(super) fn from_runtime_namespace(namespace: &RuntimeStateNamespace) -> Self {
        Self::new(namespace.redis_prefix("management-session", "v2"))
    }

    fn new(prefix: impl Into<Arc<str>>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    #[cfg(test)]
    pub(in crate::web::management) fn from_prefix(prefix: impl Into<Arc<str>>) -> Self {
        Self::new(prefix)
    }

    pub(super) fn session_key(&self, sid: &str) -> String {
        format!("{}:session:{sid}", self.prefix)
    }

    pub(super) fn session_key_prefix(&self) -> String {
        format!("{}:session:", self.prefix)
    }

    pub(super) fn all_sessions_key(&self) -> String {
        format!("{}:sessions", self.prefix)
    }

    pub(super) fn expiries_key(&self) -> String {
        format!("{}:expiries", self.prefix)
    }
}
