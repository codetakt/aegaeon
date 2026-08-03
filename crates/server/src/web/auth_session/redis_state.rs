use super::{AuthSession, UpstreamLogoutSession};
use crate::config::RuntimeStateNamespace;
use crate::upstream::{UpstreamClaimReleasePolicy, UpstreamLogoutRecoveryPolicy};
use aegaeon_crypto::hash::Sha256Hasher;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct RedisAuthSessionKeyspace {
    prefix: Arc<str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RedisAuthSession {
    pub(super) user_id: String,
    pub(super) created_at_epoch_secs: u64,
    pub(super) auth_time_epoch_secs: u64,
    pub(super) expires_at_epoch_secs: u64,
    pub(super) acr: Option<String>,
    pub(super) claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub(super) upstream_logout: Option<RedisUpstreamLogoutSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RedisUpstreamLogoutSession {
    issuer: String,
    end_session_endpoint: Option<String>,
    back_channel: bool,
    session_hint_claim: Option<String>,
    session_hint_value: Option<String>,
    recovery_policy: String,
    team_id: Option<String>,
    tenant_id: Option<String>,
    environment_id: Option<String>,
    connection_id: Option<String>,
}

fn parse_optional_uuid(value: Option<&str>) -> Option<Option<uuid::Uuid>> {
    match value {
        Some(raw) => uuid::Uuid::parse_str(raw).ok().map(Some),
        None => Some(None),
    }
}

fn optional_uuid_to_string(value: Option<uuid::Uuid>) -> Option<String> {
    value.map(|id| id.to_string())
}

impl RedisAuthSessionKeyspace {
    pub(super) fn from_runtime_namespace(namespace: &RuntimeStateNamespace) -> Self {
        Self::from_prefix(namespace.redis_prefix("auth-session", "v2"))
    }

    fn from_prefix(prefix: impl Into<Arc<str>>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    #[cfg(test)]
    pub(super) fn from_test_prefix(prefix: impl Into<Arc<str>>) -> Self {
        Self::from_prefix(prefix)
    }

    #[cfg(test)]
    pub(super) fn prefix(&self) -> &str {
        &self.prefix
    }

    pub(super) fn session_key(&self, sid: &str) -> String {
        format!("{}:session:{sid}", self.prefix)
    }

    pub(super) fn session_key_prefix(&self) -> String {
        format!("{}:session:", self.prefix)
    }

    pub(super) fn sid_user_key(&self, sid: &str) -> String {
        format!("{}:sid-user:{sid}", self.prefix)
    }

    pub(super) fn sid_user_key_prefix(&self) -> String {
        format!("{}:sid-user:", self.prefix)
    }

    pub(super) fn user_sessions_key(&self, user_id: &str) -> String {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"aegaeon:auth-session:user:v2");
        hasher.update(&(user_id.len() as u64).to_be_bytes());
        hasher.update(user_id.as_bytes());
        format!(
            "{}:user:{}",
            self.prefix,
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        )
    }

    pub(super) fn all_sessions_key(&self) -> String {
        format!("{}:sessions", self.prefix)
    }

    pub(super) fn expiries_key(&self) -> String {
        format!("{}:expiries", self.prefix)
    }
}

impl RedisUpstreamLogoutSession {
    fn from_session(session: &UpstreamLogoutSession) -> Self {
        Self {
            issuer: session.issuer.clone(),
            end_session_endpoint: session.end_session_endpoint.clone(),
            back_channel: session.back_channel,
            session_hint_claim: session.session_hint_claim.clone(),
            session_hint_value: session.session_hint_value.clone(),
            recovery_policy: session.recovery_policy.as_str().to_string(),
            team_id: optional_uuid_to_string(session.team_id),
            tenant_id: optional_uuid_to_string(session.tenant_id),
            environment_id: optional_uuid_to_string(session.environment_id),
            connection_id: optional_uuid_to_string(session.connection_id),
        }
    }

    fn to_session(&self) -> Option<UpstreamLogoutSession> {
        Some(UpstreamLogoutSession {
            issuer: self.issuer.clone(),
            end_session_endpoint: self.end_session_endpoint.clone(),
            back_channel: self.back_channel,
            session_hint_claim: self.session_hint_claim.clone(),
            session_hint_value: self.session_hint_value.clone(),
            recovery_policy: UpstreamLogoutRecoveryPolicy::parse(&self.recovery_policy).ok()?,
            team_id: parse_optional_uuid(self.team_id.as_deref())?,
            tenant_id: parse_optional_uuid(self.tenant_id.as_deref())?,
            environment_id: parse_optional_uuid(self.environment_id.as_deref())?,
            connection_id: parse_optional_uuid(self.connection_id.as_deref())?,
        })
    }
}

impl RedisAuthSession {
    pub(super) fn from_session(session: &AuthSession) -> Self {
        Self {
            user_id: session.user_id.clone(),
            created_at_epoch_secs: session.created_at_epoch_secs,
            auth_time_epoch_secs: session.auth_time_epoch_secs,
            expires_at_epoch_secs: session.expires_at_epoch_secs,
            acr: session.acr.clone(),
            claim_release_policy: session.claim_release_policy.clone(),
            upstream_logout: session
                .upstream_logout
                .as_ref()
                .map(RedisUpstreamLogoutSession::from_session),
        }
    }

    pub(super) fn to_session(&self) -> Option<AuthSession> {
        let upstream_logout = match &self.upstream_logout {
            Some(session) => Some(session.to_session()?),
            None => None,
        };
        Some(AuthSession {
            user_id: self.user_id.clone(),
            created_at_epoch_secs: self.created_at_epoch_secs,
            auth_time_epoch_secs: self.auth_time_epoch_secs,
            expires_at_epoch_secs: self.expires_at_epoch_secs,
            acr: self.acr.clone(),
            claim_release_policy: self.claim_release_policy.clone(),
            upstream_logout,
        })
    }

    pub(super) fn session_is_live(session: &RedisAuthSession, now_epoch_secs: u64) -> bool {
        session.expires_at_epoch_secs > now_epoch_secs
    }
}
