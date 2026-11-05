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
    backend: SessionGrantBackend,
}

#[derive(Debug, Clone)]
enum SessionGrantBackend {
    #[cfg(any(test, kani))]
    ProcessLocal,
    Redis(RedisOidcSessionGrantCommit),
    #[cfg(not(kani))]
    Postgres(PostgresOidcSessionGrantCommit),
}

#[cfg(not(kani))]
#[derive(Debug, Clone)]
pub(crate) struct PostgresOidcSessionGrantCommit {
    pub(crate) database: crate::authcode::store::PostgresGrantDatabase,
    pub(crate) auth_digest: [u8; 32],
    pub(crate) sid: uuid::Uuid,
    pub(crate) user_id: String,
    pub(crate) client_id: String,
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
        Self {
            sid,
            backend: SessionGrantBackend::ProcessLocal,
        }
    }

    pub(crate) fn redis(redis: RedisOidcSessionGrantCommit) -> Self {
        Self {
            sid: redis.sid.clone(),
            backend: SessionGrantBackend::Redis(redis),
        }
    }

    #[cfg(not(kani))]
    pub(crate) fn postgres(postgres: PostgresOidcSessionGrantCommit) -> Self {
        Self {
            sid: postgres.sid.to_string(),
            backend: SessionGrantBackend::Postgres(postgres),
        }
    }

    #[cfg(not(kani))]
    pub(crate) fn postgres_commit(&self) -> Option<&PostgresOidcSessionGrantCommit> {
        if let SessionGrantBackend::Postgres(postgres) = &self.backend {
            Some(postgres)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(crate) fn is_process_local(&self) -> bool {
        matches!(self.backend, SessionGrantBackend::ProcessLocal)
    }

    pub(crate) fn sid(&self) -> &str {
        &self.sid
    }

    pub(crate) fn redis_commit(&self) -> Option<&RedisOidcSessionGrantCommit> {
        if let SessionGrantBackend::Redis(redis) = &self.backend {
            Some(redis)
        } else {
            None
        }
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

#[cfg(not(kani))]
pub(crate) mod delivery;
