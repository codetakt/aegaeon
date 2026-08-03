use crate::config::{RuntimeRedisAtomicGroup, RuntimeStateNamespace};
use aegaeon_crypto::hash::Sha256Hasher;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct RedisOidcSessionKeyspace {
    prefix: Arc<str>,
}

impl RedisOidcSessionKeyspace {
    pub(super) fn new(prefix: impl Into<Arc<str>>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    pub(super) fn from_authorization_code_grant_namespace(
        namespace: &RuntimeStateNamespace,
    ) -> Self {
        Self::new(namespace.redis_atomic_group_prefix(
            RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
            "oidc-logout-session",
            "v3",
        ))
    }

    #[cfg(test)]
    pub(super) fn from_test_prefix(prefix: impl Into<Arc<str>>) -> Self {
        Self::new(prefix)
    }

    pub(super) fn session_key(&self, sid: &str) -> String {
        format!("{}:session:{sid}", self.prefix)
    }

    pub(super) fn session_key_prefix(&self) -> String {
        format!("{}:session:", self.prefix)
    }

    pub(super) fn clients_key(&self, sid: &str) -> String {
        format!("{}:clients:{sid}", self.prefix)
    }

    pub(super) fn clients_key_prefix(&self) -> String {
        format!("{}:clients:", self.prefix)
    }

    fn digest_key(&self, label: &[u8], value: &str) -> String {
        let mut hasher = Sha256Hasher::new();
        hasher.update(label);
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }

    pub(super) fn auth_session_key(&self, auth_session_id: &str) -> String {
        format!(
            "{}:auth-session:{}",
            self.prefix,
            self.digest_key(
                b"aegaeon:oidc-logout-session:auth-session:v3",
                auth_session_id
            )
        )
    }

    pub(super) fn user_sessions_key(&self, user_id: &str) -> String {
        format!(
            "{}:user-sessions:{}",
            self.prefix,
            self.digest_key(b"aegaeon:oidc-logout-session:user:v3", user_id)
        )
    }

    pub(super) fn logged_out_expiries_key(&self) -> String {
        format!("{}:logged-out-expiries", self.prefix)
    }
}
