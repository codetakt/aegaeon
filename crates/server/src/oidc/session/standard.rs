#[cfg(test)]
use super::DEFAULT_LOGOUT_SESSION_TTL_SECS;
use super::{
    normalize_logout_session_ttl_secs, OidcLogoutEvent, OidcSessionContext, OidcSessionGrantCommit,
};
use crate::config::{require_shared_runtime_store_url, ConfigError, RuntimeStateNamespace};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[path = "standard/process_local.rs"]
#[cfg(test)]
mod process_local;
#[path = "redis.rs"]
mod redis_backend;
#[cfg(test)]
use process_local::Store;
use redis_backend::{RedisOidcSessionBackend, OIDC_LOGOUT_SESSION_REDIS_URL_ENV};

#[derive(Clone)]
pub struct OidcSessionStore {
    backend: OidcSessionBackend,
    logout_session_ttl_secs: u64,
}

#[derive(Clone)]
enum OidcSessionBackend {
    #[cfg(test)]
    InMemory(Arc<RwLock<Store>>),
    Redis(RedisOidcSessionBackend),
}

#[derive(Debug, Error)]
enum OidcSessionStorageError {
    #[error("OIDC session store backend unavailable: {0}")]
    BackendUnavailable(String),
}

fn try_now_epoch_secs(operation: &'static str) -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| {
            let error = OidcSessionStorageError::BackendUnavailable(format!(
                "system clock is before Unix epoch: {err}"
            ));
            oidc_session_storage_error_message(&error, operation)
        })
}

#[cfg(test)]
fn logged_out_session_expired(logged_out_at: u64, now: u64, ttl: u64) -> bool {
    logged_out_at > now || now.saturating_sub(logged_out_at) >= ttl
}

fn log_oidc_session_storage_error(error: &OidcSessionStorageError, operation: &str) {
    tracing::error!(error = %error, operation, "OIDC session store operation failed");
}

fn oidc_session_storage_error_message(
    error: &OidcSessionStorageError,
    operation: &'static str,
) -> String {
    let message = error.to_string();
    log_oidc_session_storage_error(error, operation);
    message
}

impl OidcSessionStore {
    #[cfg(test)]
    fn new_process_local_with_ttl(logout_session_ttl_secs: u64) -> Self {
        Self {
            backend: OidcSessionBackend::InMemory(Arc::new(RwLock::new(Store::new()))),
            logout_session_ttl_secs: normalize_logout_session_ttl_secs(logout_session_ttl_secs),
        }
    }

    /// Create a process-local OIDC logout/session store for tests.
    ///
    /// Production code should use [`Self::try_new_from_shared_store_env_with_ttl_secs`] so shared
    /// runtime state is required.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local_with_ttl(DEFAULT_LOGOUT_SESSION_TTL_SECS)
    }

    /// Create a process-local OIDC logout/session store with a custom TTL for tests.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_with_ttl_for_tests(logout_session_ttl_secs: u64) -> Self {
        Self::new_process_local_with_ttl(logout_session_ttl_secs)
    }

    pub fn try_new_from_shared_store_env_with_ttl_secs(
        logout_session_ttl_secs: u64,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let logout_session_ttl_secs = normalize_logout_session_ttl_secs(logout_session_ttl_secs);
        let url = require_shared_runtime_store_url(
            "OIDC logout/session store",
            OIDC_LOGOUT_SESSION_REDIS_URL_ENV,
        )?;
        let backend =
            RedisOidcSessionBackend::new(url.as_str(), runtime_state_namespace).map_err(|err| {
                ConfigError::InvalidValue {
                    key: url.env_key().to_string(),
                    value: "[redacted]".to_string(),
                    reason: err.to_string(),
                }
            })?;
        tracing::info!("OIDC session store backend: redis");
        Ok(Self {
            backend: OidcSessionBackend::Redis(backend),
            logout_session_ttl_secs,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_redis_for_test(
        url: &str,
        key: &str,
        logout_session_ttl_secs: u64,
    ) -> Result<Self, String> {
        Ok(Self {
            backend: OidcSessionBackend::Redis(
                RedisOidcSessionBackend::new_with_prefix(url, Arc::<str>::from(key.to_string()))
                    .map_err(|err| format!("redis OIDC session store: {err}"))?,
            ),
            logout_session_ttl_secs: normalize_logout_session_ttl_secs(logout_session_ttl_secs),
        })
    }

    /// Try to get the current OIDC session ID for the browser/auth session or create a new one.
    #[must_use = "handle the session store result to preserve backend failures"]
    pub fn try_get_or_create_session(
        &self,
        context: OidcSessionContext<'_>,
    ) -> Result<String, String> {
        if context.user_id.trim().is_empty() {
            return Err("OIDC session user_id must not be blank".to_string());
        }
        if context.auth_session_id.trim().is_empty() {
            return Err("OIDC auth_session_id must not be blank".to_string());
        }
        let now = try_now_epoch_secs("try_get_or_create_session")?;
        match &self.backend {
            #[cfg(test)]
            OidcSessionBackend::InMemory(store) => process_local::get_or_create_session(
                store,
                context,
                now,
                self.logout_session_ttl_secs,
            ),
            OidcSessionBackend::Redis(backend) => backend
                .get_or_create_session(context, now, self.logout_session_ttl_secs)
                .map_err(|err| {
                    oidc_session_storage_error_message(&err, "try_get_or_create_session")
                }),
        }
    }

    pub async fn try_get_or_create_session_async(
        &self,
        context: OidcSessionContext<'_>,
    ) -> Result<String, String> {
        let store = self.clone();
        let user_id = context.user_id.to_string();
        let auth_session_id = context.auth_session_id.to_string();
        tokio::task::spawn_blocking(move || {
            store.try_get_or_create_session(OidcSessionContext {
                user_id: &user_id,
                auth_session_id: &auth_session_id,
            })
        })
        .await
        .map_err(|err| format!("OIDC session store worker failed: {err}"))?
    }

    pub(crate) fn prepare_authorization_code_grant_commit(
        &self,
        context: OidcSessionContext<'_>,
        client_id: &str,
    ) -> Result<OidcSessionGrantCommit, String> {
        if context.user_id.trim().is_empty() {
            return Err("OIDC session user_id must not be blank".to_string());
        }
        if context.auth_session_id.trim().is_empty() {
            return Err("OIDC auth_session_id must not be blank".to_string());
        }
        if client_id.trim().is_empty() {
            return Err("OIDC session client_id must not be blank".to_string());
        }
        let now = try_now_epoch_secs("prepare_authorization_code_grant_commit")?;
        match &self.backend {
            #[cfg(test)]
            OidcSessionBackend::InMemory(_) => {
                let sid = self.try_get_or_create_session(context)?;
                match self.try_add_client(&sid, client_id)? {
                    true => Ok(OidcSessionGrantCommit::process_local_for_tests(sid)),
                    false => Err("OIDC session client association failed".to_string()),
                }
            }
            OidcSessionBackend::Redis(backend) => backend
                .prepare_authorization_code_grant_commit(
                    context,
                    client_id,
                    now,
                    self.logout_session_ttl_secs,
                )
                .map(OidcSessionGrantCommit::redis)
                .map_err(|err| {
                    oidc_session_storage_error_message(
                        &err,
                        "prepare_authorization_code_grant_commit",
                    )
                }),
        }
    }

    pub(crate) async fn prepare_authorization_code_grant_commit_async(
        &self,
        context: OidcSessionContext<'_>,
        client_id: &str,
    ) -> Result<OidcSessionGrantCommit, String> {
        let store = self.clone();
        let user_id = context.user_id.to_string();
        let auth_session_id = context.auth_session_id.to_string();
        let client_id = client_id.to_string();
        tokio::task::spawn_blocking(move || {
            store.prepare_authorization_code_grant_commit(
                OidcSessionContext {
                    user_id: &user_id,
                    auth_session_id: &auth_session_id,
                },
                &client_id,
            )
        })
        .await
        .map_err(|err| format!("OIDC session store worker failed: {err}"))?
    }

    /// Get the current session ID for the user or create a new one.
    #[must_use]
    #[cfg(test)]
    pub fn get_or_create_session(&self, user_id: &str, auth_session_id: &str) -> String {
        self.try_get_or_create_session(OidcSessionContext {
            user_id,
            auth_session_id,
        })
        .expect("test OIDC session allocation should succeed")
    }

    /// Try to associate a client with an existing live session.
    pub fn try_add_client(&self, sid: &str, client_id: &str) -> Result<bool, String> {
        let now = try_now_epoch_secs("try_add_client")?;
        match &self.backend {
            #[cfg(test)]
            OidcSessionBackend::InMemory(store) => {
                process_local::add_client(store, sid, client_id, now, self.logout_session_ttl_secs)
            }
            OidcSessionBackend::Redis(backend) => backend
                .add_client(sid, client_id, now, self.logout_session_ttl_secs)
                .map_err(|err| oidc_session_storage_error_message(&err, "try_add_client")),
        }
    }

    pub async fn try_add_client_async(
        &self,
        sid: String,
        client_id: String,
    ) -> Result<bool, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_add_client(&sid, &client_id))
            .await
            .map_err(|err| format!("OIDC session store worker failed: {err}"))?
    }

    /// Associate a client with an existing session.
    #[cfg(test)]
    pub fn add_client(&self, sid: &str, client_id: &str) {
        self.try_add_client(sid, client_id)
            .expect("test OIDC session client association should succeed");
    }

    /// Log out a session. Returns the logout event (idempotent per session).
    pub fn try_logout_by_sid(&self, sid: &str) -> Result<Option<OidcLogoutEvent>, String> {
        self.try_logout_by_sid_at(sid, try_now_epoch_secs("try_logout_by_sid")?)
    }

    pub async fn try_logout_by_sid_async(
        &self,
        sid: String,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_logout_by_sid(&sid))
            .await
            .map_err(|err| format!("OIDC session store worker failed: {err}"))?
    }

    /// Log out the OIDC session linked to an auth-session id.
    pub fn try_logout_by_auth_session_id(
        &self,
        auth_session_id: &str,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        let now = try_now_epoch_secs("try_logout_by_auth_session_id")?;
        match &self.backend {
            #[cfg(test)]
            OidcSessionBackend::InMemory(store) => {
                let sid = process_local::sid_for_auth_session(store, auth_session_id)?;
                sid.map_or(Ok(None), |sid| self.try_logout_by_sid_at(&sid, now))
            }
            OidcSessionBackend::Redis(backend) => backend
                .logout_by_auth_session_id_at(auth_session_id, now, self.logout_session_ttl_secs)
                .map_err(|err| {
                    oidc_session_storage_error_message(&err, "logout_by_auth_session_id")
                }),
        }
    }

    pub async fn try_logout_by_auth_session_id_async(
        &self,
        auth_session_id: String,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_logout_by_auth_session_id(&auth_session_id))
            .await
            .map_err(|err| format!("OIDC session store worker failed: {err}"))?
    }

    /// Log out a session. Returns the logout event (idempotent per session).
    #[must_use]
    #[cfg(test)]
    pub fn logout_by_sid(&self, sid: &str) -> Option<OidcLogoutEvent> {
        self.try_logout_by_sid(sid)
            .expect("test OIDC session logout should succeed")
    }

    /// Try to log out a session at the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when the shared backing store cannot confirm the
    /// logout mutation.
    pub(crate) fn try_logout_by_sid_at(
        &self,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<OidcLogoutEvent>, String> {
        match &self.backend {
            #[cfg(test)]
            OidcSessionBackend::InMemory(store) => process_local::logout_by_sid_at(
                store,
                sid,
                now_epoch_secs,
                self.logout_session_ttl_secs,
            ),
            OidcSessionBackend::Redis(backend) => backend
                .logout_by_sid_at(sid, now_epoch_secs, self.logout_session_ttl_secs)
                .map_err(|err| oidc_session_storage_error_message(&err, "logout_by_sid_at")),
        }
    }

    /// Log out a session at the supplied timestamp. Intended for Kani/test harnesses.
    #[cfg(test)]
    pub(crate) fn logout_by_sid_at(
        &self,
        sid: &str,
        now_epoch_secs: u64,
    ) -> Option<OidcLogoutEvent> {
        self.try_logout_by_sid_at(sid, now_epoch_secs)
            .expect("test OIDC session timestamped logout should succeed")
    }

    /// Prune logged-out sessions based on the configured TTL.
    #[cfg(test)]
    pub(crate) fn prune_expired_at(&self, now_epoch_secs: u64) {
        match &self.backend {
            #[cfg(test)]
            OidcSessionBackend::InMemory(store) => {
                process_local::prune_expired_at(
                    store,
                    now_epoch_secs,
                    self.logout_session_ttl_secs,
                );
            }
            OidcSessionBackend::Redis(backend) => {
                if let Err(err) =
                    backend.prune_expired_at(now_epoch_secs, self.logout_session_ttl_secs)
                {
                    log_oidc_session_storage_error(&err, "prune_expired_at");
                }
            }
        }
    }

    /// Log out all current sessions for a user.
    pub fn try_logout_by_user(&self, user_id: &str) -> Result<Vec<OidcLogoutEvent>, String> {
        match &self.backend {
            #[cfg(test)]
            OidcSessionBackend::InMemory(store) => {
                let now = try_now_epoch_secs("logout_by_user")?;
                process_local::logout_by_user_at(store, user_id, now, self.logout_session_ttl_secs)
            }
            OidcSessionBackend::Redis(backend) => {
                let now = try_now_epoch_secs("logout_by_user")?;
                backend
                    .logout_by_user_at(user_id, now, self.logout_session_ttl_secs)
                    .map_err(|err| oidc_session_storage_error_message(&err, "logout_by_user"))
            }
        }
    }

    pub async fn try_logout_by_user_async(
        &self,
        user_id: String,
    ) -> Result<Vec<OidcLogoutEvent>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.try_logout_by_user(&user_id))
            .await
            .map_err(|err| format!("OIDC session store worker failed: {err}"))?
    }

    /// Log out all current sessions for a user.
    #[must_use]
    #[cfg(test)]
    pub fn logout_by_user(&self, user_id: &str) -> Vec<OidcLogoutEvent> {
        self.try_logout_by_user(user_id)
            .expect("test OIDC user logout should succeed")
    }
}
