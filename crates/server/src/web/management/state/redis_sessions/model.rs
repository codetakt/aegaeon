use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::ManagementSession;
use super::error::{management_session_redis_error, ManagementSessionStorageError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RedisManagementSession {
    pub(super) administrator_id: String,
    pub(super) created_at_epoch_secs: u64,
}

impl RedisManagementSession {
    pub(super) fn from_session(session: &ManagementSession) -> Self {
        Self {
            administrator_id: session.administrator_id.to_string(),
            created_at_epoch_secs: session.created_at_epoch_secs,
        }
    }

    pub(super) fn to_session(&self) -> Option<ManagementSession> {
        Some(ManagementSession::human(
            Uuid::parse_str(&self.administrator_id).ok()?,
            self.created_at_epoch_secs,
        ))
    }

    pub(super) fn decode(payload: &str) -> Result<Self, redis::RedisError> {
        serde_json::from_str::<Self>(payload)
            .map_err(|err| management_session_redis_error(err.to_string()))
    }

    pub(super) fn encode(&self) -> Result<String, ManagementSessionStorageError> {
        serde_json::to_string(self).map_err(|err| {
            ManagementSessionStorageError::BackendUnavailable(
                management_session_redis_error(err.to_string()).to_string(),
            )
        })
    }

    pub(super) fn is_live(&self, now_epoch_secs: u64, ttl_secs: u64) -> bool {
        now_epoch_secs
            .checked_sub(self.created_at_epoch_secs)
            .is_some_and(|age| age < ttl_secs)
    }

    pub(super) fn retention_secs(
        &self,
        now_epoch_secs: u64,
        ttl_secs: u64,
    ) -> Result<i64, ManagementSessionStorageError> {
        if !self.is_live(now_epoch_secs, ttl_secs) {
            return Ok(1);
        }
        let age = now_epoch_secs.saturating_sub(self.created_at_epoch_secs);
        ttl_secs
            .saturating_sub(age)
            .max(1)
            .try_into()
            .map_err(|_| ManagementSessionStorageError::RetentionOverflow)
    }

    pub(super) fn expires_at_epoch_secs(
        &self,
        ttl_secs: u64,
    ) -> Result<u64, ManagementSessionStorageError> {
        self.created_at_epoch_secs
            .checked_add(ttl_secs)
            .ok_or(ManagementSessionStorageError::RetentionOverflow)
    }
}
