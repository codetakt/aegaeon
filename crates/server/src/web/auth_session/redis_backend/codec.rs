use super::super::redis_state::RedisAuthSession;
use super::{AuthSessionStorageError, RedisAuthSessionBackend};

fn redis_auth_session_error(message: impl Into<String>) -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::TypeError,
        "auth session store state codec error",
        message.into(),
    ))
}

impl RedisAuthSessionBackend {
    pub(super) fn decode_session(payload: &str) -> Result<RedisAuthSession, redis::RedisError> {
        serde_json::from_str::<RedisAuthSession>(payload)
            .map_err(|err| redis_auth_session_error(err.to_string()))
    }

    pub(super) fn encode_session(
        session: &RedisAuthSession,
    ) -> Result<String, AuthSessionStorageError> {
        serde_json::to_string(session).map_err(|err| {
            AuthSessionStorageError::BackendUnavailable(
                redis_auth_session_error(err.to_string()).to_string(),
            )
        })
    }

    pub(super) fn retention_secs(
        expires_at_epoch_secs: u64,
        now_epoch_secs: u64,
    ) -> Result<i64, AuthSessionStorageError> {
        expires_at_epoch_secs
            .saturating_sub(now_epoch_secs)
            .max(1)
            .try_into()
            .map_err(|_| AuthSessionStorageError::RetentionOverflow)
    }
}
