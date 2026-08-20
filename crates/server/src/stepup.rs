use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::config::{
    require_shared_runtime_store_url, valid_stepup_challenge_ttl_secs, ConfigError,
    RuntimeStateNamespace,
};
#[cfg(test)]
use crate::config::{DEFAULT_STEPUP_CHALLENGE_TTL_SECS, MAX_STEPUP_CHALLENGE_TTL_SECS};

mod keyspace;
#[cfg(test)]
mod process_local;
mod redis_backend;
mod scripts;

#[cfg(test)]
use self::process_local::ProcessLocalStepUpStoreBackend;
use self::redis_backend::RedisStepUpStoreBackend;

const STEPUP_REDIS_URL_ENV: &str = "AEGAEON_STEPUP_REDIS_URL";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpChallenge {
    pub id: String,
    pub client_id: String,
    pub session_id: String,
    pub request_id: String,
    pub issued_at_epoch_secs: u64,
    pub expires_at_epoch_secs: u64,
    pub completed: bool,
}

#[derive(Clone)]
pub struct StepUpStore {
    backend: StepUpStoreBackend,
    ttl: Duration,
}

#[derive(Clone)]
enum StepUpStoreBackend {
    #[cfg(test)]
    ProcessLocal(ProcessLocalStepUpStoreBackend),
    Redis(RedisStepUpStoreBackend),
}

impl StepUpStore {
    pub fn try_from_shared_store_env_with_ttl_secs(
        ttl_secs: u64,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        if !valid_stepup_challenge_ttl_secs(ttl_secs) {
            return Err(ConfigError::InvalidNumberRange {
                key: "stepup_challenge_ttl_seconds".to_string(),
                value: ttl_secs.to_string(),
                expectation: "a value in 1..=600 seconds".to_string(),
            });
        }
        let ttl = Duration::from_secs(ttl_secs);
        let url =
            require_shared_runtime_store_url("step-up challenge store", STEPUP_REDIS_URL_ENV)?;
        let backend =
            RedisStepUpStoreBackend::new(url.as_str(), runtime_state_namespace).map_err(|err| {
                ConfigError::InvalidValue {
                    key: url.env_key().to_string(),
                    value: "[redacted]".to_string(),
                    reason: err.to_string(),
                }
            })?;
        tracing::info!("step-up store backend: redis");
        Ok(Self {
            backend: StepUpStoreBackend::Redis(backend),
            ttl,
        })
    }

    #[cfg(test)]
    fn new_process_local_with_ttl(ttl: Duration) -> Self {
        let ttl = Duration::from_secs(ttl.as_secs().clamp(1, MAX_STEPUP_CHALLENGE_TTL_SECS));
        Self {
            backend: StepUpStoreBackend::ProcessLocal(ProcessLocalStepUpStoreBackend::new()),
            ttl,
        }
    }

    /// Create a process-local step-up challenge store for tests.
    ///
    /// Production code should use [`Self::try_from_shared_store_env_with_ttl_secs`] so shared
    /// runtime state is required.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local_with_ttl(Duration::from_secs(DEFAULT_STEPUP_CHALLENGE_TTL_SECS))
    }

    /// Create a process-local step-up challenge store with a custom TTL for tests.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_with_ttl_for_tests(ttl: Duration) -> Self {
        Self::new_process_local_with_ttl(ttl)
    }

    pub fn try_issue_challenge(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<StepUpChallenge>, String> {
        let id = uuid::Builder::from_random_bytes(aegaeon_crypto::rand::random_array())
            .into_uuid()
            .to_string();
        let Some(expires_at) = now_epoch_secs.checked_add(self.ttl.as_secs()) else {
            return Ok(None);
        };
        let challenge = StepUpChallenge {
            id: id.clone(),
            client_id: client_id.to_string(),
            session_id: session_id.to_string(),
            request_id: request_id.to_string(),
            issued_at_epoch_secs: now_epoch_secs,
            expires_at_epoch_secs: expires_at,
            completed: false,
        };

        match &self.backend {
            #[cfg(test)]
            StepUpStoreBackend::ProcessLocal(backend) => backend.issue_challenge(&challenge)?,
            StepUpStoreBackend::Redis(backend) => {
                backend
                    .issue_challenge(&challenge, now_epoch_secs)
                    .map_err(|err| err.to_string())?;
            }
        }

        Ok(Some(challenge))
    }

    #[must_use]
    #[cfg(test)]
    pub fn issue_challenge(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Option<StepUpChallenge> {
        self.try_issue_challenge(client_id, session_id, request_id, now_epoch_secs)
            .expect("test step-up challenge issue should succeed")
    }

    pub fn try_complete_for_request(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Result<Option<StepUpChallenge>, String> {
        match &self.backend {
            #[cfg(test)]
            StepUpStoreBackend::ProcessLocal(backend) => {
                backend.complete_for_request(client_id, session_id, request_id, now_epoch_secs)
            }
            StepUpStoreBackend::Redis(backend) => backend
                .complete_for_request(client_id, session_id, request_id, now_epoch_secs)
                .map_err(|err| err.to_string()),
        }
    }

    #[must_use]
    #[cfg(test)]
    pub fn complete_for_request(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Option<StepUpChallenge> {
        self.try_complete_for_request(client_id, session_id, request_id, now_epoch_secs)
            .expect("test step-up challenge completion should succeed")
    }

    pub fn try_consume_completed(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> Result<bool, String> {
        match &self.backend {
            #[cfg(test)]
            StepUpStoreBackend::ProcessLocal(backend) => {
                backend.consume_completed(client_id, session_id, request_id, now_epoch_secs)
            }
            StepUpStoreBackend::Redis(backend) => backend
                .consume_completed(client_id, session_id, request_id, now_epoch_secs)
                .map_err(|err| err.to_string()),
        }
    }

    #[must_use]
    #[cfg(test)]
    pub fn consume_completed(
        &self,
        client_id: &str,
        session_id: &str,
        request_id: &str,
        now_epoch_secs: u64,
    ) -> bool {
        self.try_consume_completed(client_id, session_id, request_id, now_epoch_secs)
            .expect("test step-up challenge consumption should succeed")
    }

    pub fn try_cleanup_expired(&self) -> Result<(), String> {
        let now = now_epoch_secs()?;
        match &self.backend {
            #[cfg(test)]
            StepUpStoreBackend::ProcessLocal(backend) => backend.cleanup_expired(now),
            StepUpStoreBackend::Redis(backend) => {
                backend.cleanup_expired(now).map_err(|err| err.to_string())
            }
        }
    }

    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test step-up cleanup should succeed");
    }
}

fn request_key(client_id: &str, session_id: &str, request_id: &str) -> String {
    format!("{client_id}::{session_id}::{request_id}")
}

#[cfg(test)]
fn challenge_valid(challenge: &StepUpChallenge, now_epoch_secs: u64) -> bool {
    challenge.issued_at_epoch_secs <= now_epoch_secs
        && now_epoch_secs < challenge.expires_at_epoch_secs
}

fn now_epoch_secs() -> Result<u64, String> {
    crate::util::now_unix_epoch_secs().map_err(|err| {
        crate::util::log_clock_error("step-up clock", &err);
        err.to_string()
    })
}

#[cfg(test)]
mod tests;
