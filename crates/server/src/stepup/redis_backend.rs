#[cfg(test)]
use std::sync::Arc;

use thiserror::Error;

use super::keyspace::RedisStepUpKeyspace;
use super::{request_key, scripts, StepUpChallenge};
use crate::config::RuntimeStateNamespace;

#[derive(Clone)]
pub(super) struct RedisStepUpStoreBackend {
    client: redis::Client,
    keyspace: RedisStepUpKeyspace,
}

#[derive(Debug, Error)]
pub(super) enum StepUpStorageError {
    #[error("step-up store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("step-up store retention cannot be represented")]
    RetentionOverflow,
}

impl RedisStepUpStoreBackend {
    pub(super) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, StepUpStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                keyspace: RedisStepUpKeyspace::from_runtime_namespace(namespace),
            })
            .map_err(|err| StepUpStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(super) fn new_with_prefix(
        url: &str,
        prefix: impl Into<Arc<str>>,
    ) -> Result<Self, StepUpStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                keyspace: RedisStepUpKeyspace::from_test_prefix(prefix),
            })
            .map_err(|err| StepUpStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn issue_challenge(
        &self,
        challenge: &StepUpChallenge,
        now_epoch_secs: u64,
    ) -> Result<(), StepUpStorageError> {
        let request_lookup_key = request_key(
            &challenge.client_id,
            &challenge.session_id,
            &challenge.request_id,
        );
        let request_redis_key = self.keyspace.request_key(&request_lookup_key);
        let retention_secs = Self::retention_secs(challenge.expires_at_epoch_secs, now_epoch_secs)?;
        let mut conn = self.connection()?;
        redis::Script::new(scripts::ISSUE_CHALLENGE)
            .key(self.keyspace.challenge_key(&challenge.id))
            .key(request_redis_key)
            .key(self.keyspace.expiries_key())
            .arg(&challenge.id)
            .arg(&challenge.client_id)
            .arg(&challenge.session_id)
            .arg(&challenge.request_id)
            .arg(challenge.issued_at_epoch_secs)
            .arg(challenge.expires_at_epoch_secs)
            .arg(retention_secs)
            .arg(now_epoch_secs)
            .arg(self.keyspace.challenge_key_prefix())
            .invoke::<i64>(&mut conn)
            .map(|_| ())
            .map_err(|err| StepUpStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn complete_for_request(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<StepUpChallenge>, StepUpStorageError> {
        let request_lookup_key = request_key(client_id, session_id, request_id);
        let request_redis_key = self.keyspace.request_key(&request_lookup_key);
        let mut conn = self.connection()?;
        redis::Script::new(scripts::COMPLETE_FOR_REQUEST)
            .key(request_redis_key)
            .key(self.keyspace.expiries_key())
            .arg(now_epoch_secs)
            .arg(self.keyspace.challenge_key_prefix())
            .invoke::<Option<Vec<String>>>(&mut conn)
            .map(|values| values.and_then(Self::challenge_from_values))
            .map_err(|err| StepUpStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn consume_completed(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Result<bool, StepUpStorageError> {
        let request_lookup_key = request_key(client_id, session_id, request_id);
        let request_redis_key = self.keyspace.request_key(&request_lookup_key);
        let mut conn = self.connection()?;
        redis::Script::new(scripts::CONSUME_COMPLETED)
            .key(request_redis_key)
            .key(self.keyspace.expiries_key())
            .arg(now_epoch_secs)
            .arg(self.keyspace.challenge_key_prefix())
            .invoke::<i64>(&mut conn)
            .map(|value| value == 1)
            .map_err(|err| StepUpStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn cleanup_expired(&self, now_epoch_secs: u64) -> Result<(), StepUpStorageError> {
        let mut conn = self.connection()?;
        redis::Script::new(scripts::CLEANUP_EXPIRED)
            .key(self.keyspace.expiries_key())
            .arg(now_epoch_secs)
            .arg(self.keyspace.challenge_key_prefix())
            .invoke::<i64>(&mut conn)
            .map(|_| ())
            .map_err(|err| StepUpStorageError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, StepUpStorageError> {
        self.client
            .get_connection()
            .map_err(|err| StepUpStorageError::BackendUnavailable(err.to_string()))
    }

    fn retention_secs(
        expires_at_epoch_secs: u64,
        now_epoch_secs: u64,
    ) -> Result<i64, StepUpStorageError> {
        expires_at_epoch_secs
            .saturating_sub(now_epoch_secs)
            .max(1)
            .try_into()
            .map_err(|_| StepUpStorageError::RetentionOverflow)
    }

    fn challenge_from_values(values: Vec<String>) -> Option<StepUpChallenge> {
        let [id, client_id, session_id, request_id, issued_at, expires_at, completed]: [String; 7] =
            values.try_into().ok()?;
        Some(StepUpChallenge {
            id,
            client_id,
            session_id,
            request_id,
            issued_at_epoch_secs: issued_at.parse().ok()?,
            expires_at_epoch_secs: expires_at.parse().ok()?,
            completed: completed == "1",
        })
    }
}
