use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcLogoutEvent {
    pub sid: String,
    pub user_id: String,
    pub jti: String,
    pub client_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OidcSessionContext<'a> {
    pub user_id: &'a str,
    pub auth_session_id: &'a str,
}

#[derive(Debug, Clone)]
pub(crate) struct OidcSessionGrantCommit {
    sid: String,
    redis: Option<RedisOidcSessionGrantCommit>,
}

#[derive(Debug, Clone)]
pub(crate) struct RedisOidcSessionGrantCommit {
    pub(crate) url: Arc<str>,
    pub(crate) auth_session_key: String,
    pub(crate) session_key: String,
    pub(crate) logged_out_expiries_key: String,
    pub(crate) user_sessions_key: String,
    pub(crate) clients_key: String,
    pub(crate) user_id: String,
    pub(crate) sid: String,
    pub(crate) now_epoch_secs: u64,
    pub(crate) ttl_secs: u64,
    pub(crate) session_key_prefix: String,
    pub(crate) clients_key_prefix: String,
    pub(crate) client_id: String,
}

impl OidcSessionGrantCommit {
    #[cfg(any(test, kani))]
    pub(crate) fn process_local_for_tests(sid: String) -> Self {
        Self { sid, redis: None }
    }

    pub(crate) fn redis(redis: RedisOidcSessionGrantCommit) -> Self {
        Self {
            sid: redis.sid.clone(),
            redis: Some(redis),
        }
    }

    pub(crate) fn sid(&self) -> &str {
        &self.sid
    }

    pub(crate) fn redis_commit(&self) -> Option<&RedisOidcSessionGrantCommit> {
        self.redis.as_ref()
    }
}

pub const DEFAULT_LOGOUT_SESSION_TTL_SECS: u64 = 600;
pub const MAX_LOGOUT_SESSION_TTL_SECS: u64 = 86_400;

#[must_use]
pub const fn valid_logout_session_ttl_secs(value: u64) -> bool {
    value > 0 && value <= MAX_LOGOUT_SESSION_TTL_SECS
}

#[must_use]
pub const fn normalize_logout_session_ttl_secs(value: u64) -> u64 {
    if value == 0 {
        1
    } else if value > MAX_LOGOUT_SESSION_TTL_SECS {
        MAX_LOGOUT_SESSION_TTL_SECS
    } else {
        value
    }
}

#[cfg(not(kani))]
#[path = "session/standard.rs"]
mod imp;

#[cfg(kani)]
#[path = "session/kani.rs"]
mod imp;

#[cfg(kani)]
pub(crate) use imp::BoundedKaniSessionStore;
pub use imp::OidcSessionStore;

#[cfg(all(test, not(kani)))]
mod tests;
