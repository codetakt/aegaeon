use aegaeon_crypto::hash::Sha256Hasher;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::sync::Arc;

use crate::config::RuntimeStateNamespace;

#[derive(Clone)]
pub(super) struct RedisStepUpKeyspace {
    pub(super) prefix: Arc<str>,
}

impl RedisStepUpKeyspace {
    pub(super) fn new(prefix: impl Into<Arc<str>>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    pub(super) fn from_runtime_namespace(namespace: &RuntimeStateNamespace) -> Self {
        Self::new(namespace.redis_prefix("stepup", "v2"))
    }

    #[cfg(test)]
    pub(super) fn from_test_prefix(prefix: impl Into<Arc<str>>) -> Self {
        Self::new(prefix)
    }

    pub(super) fn challenge_key(&self, challenge_id: &str) -> String {
        format!("{}:challenge:{challenge_id}", self.prefix)
    }

    pub(super) fn challenge_key_prefix(&self) -> String {
        format!("{}:challenge:", self.prefix)
    }

    pub(super) fn request_key(&self, request_key: &str) -> String {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"aegaeon:stepup:request:v2");
        hasher.update(&(request_key.len() as u64).to_be_bytes());
        hasher.update(request_key.as_bytes());
        format!(
            "{}:request:{}",
            self.prefix,
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        )
    }

    pub(super) fn expiries_key(&self) -> String {
        format!("{}:expiries", self.prefix)
    }
}
