#[cfg(test)]
mod process_local;
mod redis_backend;
mod scripts;

#[cfg(test)]
pub(super) use self::process_local::InMemoryAuthCodeBackend;
pub(super) use self::redis_backend::RedisAuthCodeBackend;

use super::types::AuthorizationCode;
#[cfg(test)]
use super::types::AuthorizationCodeInput;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};
use thiserror::Error;

const AUTH_CODE_EXCHANGE_LOCK_TTL_MS: u64 = 30_000;
const AUTH_CODE_EXCHANGE_LOCK_RETRIES: usize = 100;
const AUTH_CODE_EXCHANGE_LOCK_RETRY_DELAY_MS: u64 = 20;

#[derive(Clone, Debug, Default)]
pub struct AuthCodeSnapshot {
    pub codes: HashMap<String, AuthorizationCode>,
    pub used_states: HashSet<String>,
    pub used_nonces: HashSet<String>,
    pub version: u64,
}

#[derive(Debug, Error)]
pub(in crate::authcode) enum AuthCodeStorageError {
    #[error("authorization code store backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("authorization code store TTL cannot be represented")]
    RetentionOverflow,

    #[error("authorization code payload cannot be serialized: {0}")]
    Serialize(String),

    #[cfg(test)]
    #[error("authorization code payload changed before grant commit")]
    PayloadMismatch,
}

#[derive(Debug, Error)]
pub(in crate::authcode) enum StoreCodeError {
    #[error("State already used")]
    StateUsed,

    #[error("Nonce already used")]
    NonceUsed,

    #[error("Authorization code already exists")]
    CodeCollision,

    #[error("Authorization code is already expired")]
    Expired,

    #[error("Pushed authorization request is missing or already consumed")]
    PushedAuthorizationRequestMissing,

    #[error("Request Object jti already used")]
    RequestObjectJtiReplay,

    #[error(transparent)]
    Storage(#[from] AuthCodeStorageError),
}

pub(in crate::authcode) struct AuthCodeRedisCommitContext {
    pub(in crate::authcode) url: std::sync::Arc<str>,
    pub(in crate::authcode) code_key: String,
    pub(in crate::authcode) version_key: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ParAuthorizationCodeCommit {
    pub(crate) url: std::sync::Arc<str>,
    pub(crate) request_key: String,
    pub(crate) reservation_key: String,
    pub(crate) expected_continuation: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RequestObjectJtiAuthorizationCodeCommit {
    pub(crate) url: std::sync::Arc<str>,
    pub(crate) key: String,
    pub(crate) ttl_ms: i64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AuthorizationCodeOneTimeInputCommit {
    pub(crate) par: Option<ParAuthorizationCodeCommit>,
    pub(crate) request_object_jti: Option<RequestObjectJtiAuthorizationCodeCommit>,
}

impl AuthorizationCodeOneTimeInputCommit {
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.par.is_none() && self.request_object_jti.is_none()
    }
}

pub(in crate::authcode) struct AuthCodeExchangeLock {
    inner: Option<AuthCodeExchangeLockInner>,
}

enum AuthCodeExchangeLockInner {
    Noop,
    Redis {
        backend: Box<RedisAuthCodeBackend>,
        lock_key: String,
        lock_token: String,
    },
}

impl AuthCodeExchangeLock {
    fn noop() -> Self {
        Self {
            inner: Some(AuthCodeExchangeLockInner::Noop),
        }
    }

    fn redis(backend: RedisAuthCodeBackend, lock_key: String, lock_token: String) -> Self {
        Self {
            inner: Some(AuthCodeExchangeLockInner::Redis {
                backend: Box::new(backend),
                lock_key,
                lock_token,
            }),
        }
    }

    pub(in crate::authcode) fn release(mut self) {
        self.release_inner();
    }

    pub(in crate::authcode) async fn release_async(mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        if let Err(err) =
            tokio::task::spawn_blocking(move || release_exchange_lock_inner(inner)).await
        {
            tracing::warn!(
                target: "authcode",
                error = %err,
                "authorization-code exchange lock release worker failed"
            );
        }
    }

    fn release_inner(&mut self) {
        if let Some(inner) = self.inner.take() {
            release_exchange_lock_inner(inner);
        }
    }
}

impl Drop for AuthCodeExchangeLock {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        release_exchange_lock_in_background(inner);
    }
}

fn release_exchange_lock_inner(inner: AuthCodeExchangeLockInner) {
    match inner {
        AuthCodeExchangeLockInner::Noop => {}
        AuthCodeExchangeLockInner::Redis {
            backend,
            lock_key,
            lock_token,
        } => backend.release_exchange_lock(&lock_key, &lock_token),
    }
}

fn release_exchange_lock_in_background(inner: AuthCodeExchangeLockInner) {
    match inner {
        AuthCodeExchangeLockInner::Noop => {}
        inner @ AuthCodeExchangeLockInner::Redis { .. } => {
            let result = std::thread::Builder::new()
                .name("aegaeon-auth-code-lock-release".to_string())
                .spawn(move || release_exchange_lock_inner(inner));
            if let Err(err) = result {
                tracing::warn!(
                    target: "authcode",
                    error = %err,
                    "failed to spawn authorization-code exchange lock release worker; relying on Redis lock TTL"
                );
            }
        }
    }
}

pub(super) trait AuthCodeBackend: Send + Sync {
    fn redis_commit_context(&self, _code: &str) -> Option<AuthCodeRedisCommitContext> {
        None
    }
    fn acquire_exchange_lock(
        &self,
        _code: &str,
    ) -> Result<AuthCodeExchangeLock, AuthCodeStorageError> {
        Ok(AuthCodeExchangeLock::noop())
    }
    #[cfg(test)]
    fn snapshot(&self) -> Result<AuthCodeSnapshot, AuthCodeStorageError>;
    fn get_code(&self, code: &str) -> Result<Option<AuthorizationCode>, AuthCodeStorageError>;
    fn store_code(&self, code: AuthorizationCode) -> Result<String, StoreCodeError>;
    fn store_code_with_one_time_inputs(
        &self,
        code: AuthorizationCode,
        one_time_inputs: AuthorizationCodeOneTimeInputCommit,
    ) -> Result<String, StoreCodeError> {
        if one_time_inputs.is_empty() {
            self.store_code(code)
        } else {
            Err(StoreCodeError::Storage(
                AuthCodeStorageError::BackendUnavailable(
                    "authorization-code one-time input commit requires Redis-backed stores"
                        .to_string(),
                ),
            ))
        }
    }
    fn use_code(&self, code: &str) -> Result<Option<AuthorizationCode>, AuthCodeStorageError>;
    #[cfg(test)]
    fn use_code_if_payload_matches(
        &self,
        code: &str,
        expected_payload: &str,
    ) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        let Some(current) = self.get_code(code)? else {
            return Ok(None);
        };
        let current_payload = serde_json::to_string(&current)
            .map_err(|err| AuthCodeStorageError::Serialize(err.to_string()))?;
        if current_payload != expected_payload {
            return Err(AuthCodeStorageError::PayloadMismatch);
        }
        self.use_code(code)
    }
    fn cleanup_expired(&self) -> Result<(), AuthCodeStorageError>;
    fn state_count(&self) -> Result<usize, AuthCodeStorageError>;
    fn nonce_count(&self) -> Result<usize, AuthCodeStorageError>;
}

fn remaining_ttl(expires_at: SystemTime) -> Option<Duration> {
    expires_at.duration_since(SystemTime::now()).ok()
}

fn ttl_millis_i64(ttl: Duration) -> Result<i64, AuthCodeStorageError> {
    ttl.as_millis()
        .try_into()
        .map(|ttl_ms: i64| ttl_ms.max(1))
        .map_err(|_| AuthCodeStorageError::RetentionOverflow)
}

fn auth_code_key_digest(value: &str) -> String {
    let mut hasher = aegaeon_crypto::hash::Sha256Hasher::new();
    hasher.update(b"aegaeon:authcode:v2");
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_code(state: Option<&str>, nonce: Option<&str>) -> AuthorizationCode {
        AuthorizationCode::new(AuthorizationCodeInput {
            scope: Some("openid".to_string()),
            state: state.map(str::to_string),
            nonce: nonce.map(str::to_string),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            ..AuthorizationCodeInput::new(
                "client".to_string(),
                "user".to_string(),
                Some("https://client.example/cb".to_string()),
            )
        })
    }

    #[test]
    fn auth_code_key_digest_is_length_delimited() {
        assert_ne!(auth_code_key_digest("ab"), auth_code_key_digest("a:b"));
    }

    #[test]
    fn ttl_millis_rejects_unrepresentable_ttl() {
        assert!(matches!(
            ttl_millis_i64(Duration::MAX),
            Err(AuthCodeStorageError::RetentionOverflow)
        ));
    }

    #[test]
    fn in_memory_backend_rejects_authorization_code_collision() {
        let backend = InMemoryAuthCodeBackend::new(Duration::from_secs(60));
        let code = sample_code(None, None);
        let duplicate = code.clone();

        assert!(backend.store_code(code).is_ok());
        assert!(matches!(
            backend.store_code(duplicate),
            Err(StoreCodeError::CodeCollision)
        ));
    }

    #[test]
    fn in_memory_backend_rejects_expired_authorization_code() -> Result<(), String> {
        let backend = InMemoryAuthCodeBackend::new(Duration::from_secs(60));
        let mut code = sample_code(None, None);
        code.expires_at = SystemTime::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or_else(|| "expired timestamp should be representable".to_string())?;

        assert!(matches!(
            backend.store_code(code),
            Err(StoreCodeError::Expired)
        ));
        Ok(())
    }

    #[test]
    #[ignore = "requires AEGAEON_TEST_REDIS_URL"]
    fn redis_auth_code_backend_enforces_state_nonce_and_code_single_use() -> Result<(), String> {
        let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
        let Ok(url) = std::env::var(redis_url_env) else {
            return Ok(());
        };
        let backend = RedisAuthCodeBackend::new_for_tests(url.trim(), Duration::from_secs(60))
            .map_err(|err| format!("redis auth code backend: {err}"))?;
        let mut code = sample_code(Some("state-redis"), Some("nonce-redis"));
        code.code = format!("code-{}", aegaeon_crypto::rand::random_base64url(16));
        code.state = Some(format!(
            "state-{}",
            aegaeon_crypto::rand::random_base64url(16)
        ));
        code.nonce = Some(format!(
            "nonce-{}",
            aegaeon_crypto::rand::random_base64url(16)
        ));

        let code_str = backend
            .store_code(code.clone())
            .map_err(|err| format!("store code: {err}"))?;
        assert!(backend
            .get_code(&code_str)
            .map_err(|err| format!("get code: {err}"))?
            .is_some());

        let duplicate_state = AuthorizationCode {
            code: format!("code-{}", aegaeon_crypto::rand::random_base64url(16)),
            nonce: Some(format!(
                "nonce-{}",
                aegaeon_crypto::rand::random_base64url(16)
            )),
            ..code.clone()
        };
        assert!(matches!(
            backend.store_code(duplicate_state),
            Err(StoreCodeError::StateUsed)
        ));

        let duplicate_nonce = AuthorizationCode {
            code: format!("code-{}", aegaeon_crypto::rand::random_base64url(16)),
            state: Some(format!(
                "state-{}",
                aegaeon_crypto::rand::random_base64url(16)
            )),
            ..code.clone()
        };
        assert!(matches!(
            backend.store_code(duplicate_nonce),
            Err(StoreCodeError::NonceUsed)
        ));

        assert!(backend
            .use_code(&code_str)
            .map_err(|err| format!("consume code: {err}"))?
            .is_some());
        assert!(backend
            .use_code(&code_str)
            .map_err(|err| format!("consume code again: {err}"))?
            .is_none());
        Ok(())
    }
}
