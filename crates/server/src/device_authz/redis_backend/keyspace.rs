use std::sync::Arc;

use crate::config::RuntimeStateNamespace;

#[derive(Clone)]
pub(in crate::device_authz) struct RedisDeviceCodeKeyspace {
    pub(in crate::device_authz) prefix: Arc<str>,
}

impl RedisDeviceCodeKeyspace {
    fn new(prefix: impl Into<Arc<str>>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    pub(super) fn from_runtime_namespace(namespace: &RuntimeStateNamespace) -> Self {
        Self::new(namespace.redis_prefix("device-code", "v2"))
    }

    #[cfg(test)]
    pub(in crate::device_authz) fn from_test_prefix(prefix: impl Into<Arc<str>>) -> Self {
        Self::new(prefix)
    }

    pub(super) fn entry_key(&self, device_code_hash: &str) -> String {
        format!("{}:entry:{device_code_hash}", self.prefix)
    }

    pub(super) fn entry_key_prefix(&self) -> String {
        format!("{}:entry:", self.prefix)
    }

    pub(super) fn user_code_key(&self, user_code_lookup_key: &str) -> String {
        format!("{}:user:{}", self.prefix, user_code_lookup_key)
    }

    pub(super) fn user_code_key_prefix(&self) -> String {
        format!("{}:user:", self.prefix)
    }

    pub(super) fn expiries_key(&self) -> String {
        format!("{}:expiries", self.prefix)
    }
}
