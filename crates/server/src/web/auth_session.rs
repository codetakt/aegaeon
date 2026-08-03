#[cfg(test)]
mod process_local;
mod redis_backend;
mod redis_state;
mod types;

#[cfg(test)]
use process_local::ProcessLocalAuthSessionBackend;
use redis_backend::{AuthSessionStorageError, RedisAuthSessionBackend};
pub(in crate::web) use types::{AuthSession, AuthSessionTimes, UpstreamLogoutSession};

use crate::config::{
    require_shared_runtime_store_url, valid_auth_max_sessions, valid_auth_session_ttl_secs,
    ConfigError, RuntimeStateNamespace, MAX_AUTH_SESSION_TTL_SECS,
};
#[cfg(test)]
use crate::config::{DEFAULT_AUTH_MAX_SESSIONS, DEFAULT_AUTH_SESSION_TTL_SECS};
use crate::management::types::PolicyDocument;
use crate::upstream::UpstreamClaimReleasePolicy;
use crate::util;

const AUTH_SESSION_REDIS_URL_ENV: &str = "AEGAEON_AUTH_SESSION_REDIS_URL";

#[derive(Clone)]
pub struct AuthSessionStore {
    backend: AuthSessionBackend,
    ttl_secs: u64,
    max_sessions: usize,
}

#[derive(Clone)]
enum AuthSessionBackend {
    #[cfg(test)]
    InMemory(ProcessLocalAuthSessionBackend),
    Redis(RedisAuthSessionBackend),
}

fn now_epoch_secs() -> Result<u64, String> {
    util::now_unix_epoch_secs().map_err(|err| {
        util::log_clock_error("web auth session clock", &err);
        err.to_string()
    })
}

fn log_auth_session_storage_error(error: &AuthSessionStorageError, operation: &str) {
    tracing::error!(error = %error, operation, "auth session store operation failed");
}

impl AuthSessionStore {
    pub fn try_from_management_policy(
        policy: &PolicyDocument,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let max_sessions = usize::try_from(policy.auth_max_sessions).map_err(|_| {
            ConfigError::InvalidNumberRange {
                key: "auth_max_sessions".to_string(),
                value: policy.auth_max_sessions.to_string(),
                expectation: "a value in 1..=1000000 sessions".to_string(),
            }
        })?;
        Self::try_with_policy_limits(
            u64::from(policy.auth_session_ttl_seconds),
            max_sessions,
            runtime_state_namespace,
        )
    }

    fn try_with_policy_limits(
        ttl_secs: u64,
        max_sessions: usize,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        if !valid_auth_session_ttl_secs(ttl_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "auth_session_ttl_seconds".to_string(),
                value: ttl_secs.to_string(),
                expectation: "a value in 1..=86400 seconds".to_string(),
            });
        }
        if !valid_auth_max_sessions(max_sessions) {
            return Err(ConfigError::InvalidNumberRange {
                key: "auth_max_sessions".to_string(),
                value: max_sessions.to_string(),
                expectation: "a value in 1..=1000000 sessions".to_string(),
            });
        }
        let url = require_shared_runtime_store_url(
            "browser auth-session store",
            AUTH_SESSION_REDIS_URL_ENV,
        )?;
        let backend =
            RedisAuthSessionBackend::new(url.as_str(), runtime_state_namespace).map_err(|err| {
                ConfigError::InvalidValue {
                    key: url.env_key().to_string(),
                    value: "[redacted]".to_string(),
                    reason: err.to_string(),
                }
            })?;
        tracing::info!("auth session store backend: redis");
        Ok(Self {
            backend: AuthSessionBackend::Redis(backend),
            ttl_secs: ttl_secs.clamp(1, MAX_AUTH_SESSION_TTL_SECS),
            max_sessions: max_sessions.max(1),
        })
    }

    #[cfg(test)]
    fn new_process_local_with_limits(ttl_secs: u64, max_sessions: usize) -> Self {
        Self {
            backend: AuthSessionBackend::InMemory(ProcessLocalAuthSessionBackend::new()),
            ttl_secs: ttl_secs.clamp(1, MAX_AUTH_SESSION_TTL_SECS),
            max_sessions: max_sessions.max(1),
        }
    }

    /// Create a process-local browser auth-session store for tests.
    ///
    /// Production code should use [`Self::try_from_management_policy`] so management policy and
    /// shared runtime state are required.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local_with_limits(
            DEFAULT_AUTH_SESSION_TTL_SECS,
            DEFAULT_AUTH_MAX_SESSIONS,
        )
    }

    #[cfg(test)]
    #[must_use]
    pub(super) fn new_process_local_with_limits_for_tests(
        ttl_secs: u64,
        max_sessions: usize,
    ) -> Self {
        Self::new_process_local_with_limits(ttl_secs, max_sessions)
    }

    #[must_use]
    pub(super) fn cookie_ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    pub(super) fn try_get(&self, sid: &str) -> Result<Option<AuthSession>, String> {
        let now = now_epoch_secs()?;
        match &self.backend {
            #[cfg(test)]
            AuthSessionBackend::InMemory(backend) => backend.get(sid, now),
            AuthSessionBackend::Redis(backend) => backend.get(sid, now).map_err(|err| {
                let message = err.to_string();
                log_auth_session_storage_error(&err, "get");
                message
            }),
        }
    }

    pub(super) async fn try_get_async(&self, sid: String) -> Result<Option<AuthSession>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_get(&sid))
            .await
            .map_err(|err| format!("auth session store worker failed: {err}"))?
    }

    pub(super) fn try_create(
        &self,
        user_id: &str,
        times: AuthSessionTimes,
        acr: Option<String>,
        claim_release_policy: Option<UpstreamClaimReleasePolicy>,
        upstream_logout: Option<UpstreamLogoutSession>,
    ) -> Result<Option<String>, String> {
        let sid = uuid::Uuid::new_v4().to_string();
        let Some(expires_at_epoch_secs) = times.created_at_epoch_secs.checked_add(self.ttl_secs)
        else {
            return Ok(None);
        };
        let session = AuthSession {
            user_id: user_id.to_string(),
            created_at_epoch_secs: times.created_at_epoch_secs,
            auth_time_epoch_secs: times.auth_time_epoch_secs,
            expires_at_epoch_secs,
            acr,
            claim_release_policy,
            upstream_logout,
        };
        match &self.backend {
            #[cfg(test)]
            AuthSessionBackend::InMemory(backend) => backend
                .create(
                    &sid,
                    session,
                    times.created_at_epoch_secs,
                    self.max_sessions,
                )
                .map(|()| Some(sid)),
            AuthSessionBackend::Redis(backend) => backend
                .create(
                    &sid,
                    &session,
                    times.created_at_epoch_secs,
                    self.max_sessions,
                )
                .map(|()| Some(sid.clone()))
                .map_err(|err| {
                    let message = err.to_string();
                    log_auth_session_storage_error(&err, "create");
                    message
                }),
        }
    }

    pub(super) async fn try_create_async(
        &self,
        user_id: String,
        times: AuthSessionTimes,
        acr: Option<String>,
        claim_release_policy: Option<UpstreamClaimReleasePolicy>,
        upstream_logout: Option<UpstreamLogoutSession>,
    ) -> Result<Option<String>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.try_create(&user_id, times, acr, claim_release_policy, upstream_logout)
        })
        .await
        .map_err(|err| format!("auth session store worker failed: {err}"))?
    }

    #[cfg(test)]
    pub(super) fn create(
        &self,
        user_id: &str,
        times: AuthSessionTimes,
        acr: Option<String>,
        claim_release_policy: Option<UpstreamClaimReleasePolicy>,
        upstream_logout: Option<UpstreamLogoutSession>,
    ) -> Option<String> {
        self.try_create(user_id, times, acr, claim_release_policy, upstream_logout)
            .unwrap_or_else(|err| {
                tracing::error!(error = %err, "auth session store operation failed");
                None
            })
    }

    pub(super) fn try_delete(&self, sid: &str) -> Result<bool, String> {
        match &self.backend {
            #[cfg(test)]
            AuthSessionBackend::InMemory(backend) => backend.delete_sid(sid),
            AuthSessionBackend::Redis(backend) => backend.delete_sid(sid).map_err(|err| {
                let message = err.to_string();
                log_auth_session_storage_error(&err, "delete");
                message
            }),
        }
    }

    pub(super) async fn try_delete_async(&self, sid: String) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_delete(&sid))
            .await
            .map_err(|err| format!("auth session store worker failed: {err}"))?
    }

    pub(super) fn try_delete_for_user(&self, user_id: &str) -> Result<usize, String> {
        let now = now_epoch_secs()?;
        match &self.backend {
            #[cfg(test)]
            AuthSessionBackend::InMemory(backend) => backend.delete_for_user(user_id, now),
            AuthSessionBackend::Redis(backend) => {
                backend.delete_for_user(user_id, now).map_err(|err| {
                    let message = err.to_string();
                    log_auth_session_storage_error(&err, "delete_for_user");
                    message
                })
            }
        }
    }

    pub(super) async fn try_delete_for_user_async(&self, user_id: String) -> Result<usize, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_delete_for_user(&user_id))
            .await
            .map_err(|err| format!("auth session store worker failed: {err}"))?
    }

    pub(super) fn try_list_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<(String, AuthSession)>, String> {
        let now = now_epoch_secs()?;
        match &self.backend {
            #[cfg(test)]
            AuthSessionBackend::InMemory(backend) => backend.list_for_user(user_id, now),
            AuthSessionBackend::Redis(backend) => {
                backend.list_for_user(user_id, now).map_err(|err| {
                    let message = err.to_string();
                    log_auth_session_storage_error(&err, "list_for_user");
                    message
                })
            }
        }
    }

    pub(super) async fn try_list_for_user_async(
        &self,
        user_id: String,
    ) -> Result<Vec<(String, AuthSession)>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_list_for_user(&user_id))
            .await
            .map_err(|err| format!("auth session store worker failed: {err}"))?
    }

    pub(super) fn try_delete_for_user_session(
        &self,
        user_id: &str,
        sid: &str,
    ) -> Result<bool, String> {
        let now = now_epoch_secs()?;
        match &self.backend {
            #[cfg(test)]
            AuthSessionBackend::InMemory(backend) => {
                backend.delete_for_user_session(user_id, sid, now)
            }
            AuthSessionBackend::Redis(backend) => backend
                .delete_for_user_session(user_id, sid, now)
                .map_err(|err| {
                    let message = err.to_string();
                    log_auth_session_storage_error(&err, "delete_for_user_session");
                    message
                }),
        }
    }

    pub(super) async fn try_delete_for_user_session_async(
        &self,
        user_id: String,
        sid: String,
    ) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_delete_for_user_session(&user_id, &sid))
            .await
            .map_err(|err| format!("auth session store worker failed: {err}"))?
    }

    pub fn try_cleanup_expired(&self) -> Result<usize, String> {
        let now = now_epoch_secs()?;
        match &self.backend {
            #[cfg(test)]
            AuthSessionBackend::InMemory(backend) => backend.cleanup_expired(now),
            AuthSessionBackend::Redis(backend) => {
                backend.cleanup_expired(now).map_err(|err| err.to_string())
            }
        }
    }

    #[cfg(test)]
    pub fn cleanup_expired(&self) -> usize {
        self.try_cleanup_expired()
            .expect("test auth session cleanup should succeed")
    }
}

#[cfg(test)]
mod tests;
