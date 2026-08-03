use crate::config::{require_shared_runtime_store_url, ConfigError, RuntimeStateNamespace};
use aegaeon_crypto::hash::Sha256Hasher;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[cfg(test)]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(test)]
use std::sync::RwLock;
use std::time::Duration;
#[cfg(test)]
use std::time::SystemTime;
use thiserror::Error;

#[cfg(test)]
use super::write_lock;

const CSRF_TOKEN_TTL_SECS: u64 = 600;
const CSRF_TOKEN_GENERATION_ATTEMPTS: usize = 16;
const CSRF_REDIS_KEY_PREFIX: &str = "csrf:v1";
const VALIDATE_TOKEN_SCRIPT: &str = r#"
local value = redis.call("GET", KEYS[1])
if value then
  redis.call("DEL", KEYS[1])
  return 1
end
return 0
"#;
#[cfg(test)]
const VALIDATE_TOKEN_SCRIPT_KEY_COUNT: usize = 1;
#[cfg(test)]
const VALIDATE_TOKEN_SCRIPT_ARG_COUNT: usize = 0;

fn generate_csrf_token() -> Result<String, CsrfTokenStoreError> {
    let mut bytes = [0u8; 32];
    aegaeon_crypto::rand::fill_random(&mut bytes).map_err(|err| {
        let message = "CSRF token entropy generation failed".to_string();
        tracing::error!(error = ?err, %message);
        CsrfTokenStoreError::BackendUnavailable(message)
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn ttl_millis_i64(ttl: Duration) -> Result<i64, CsrfTokenStoreError> {
    ttl.as_millis()
        .try_into()
        .map(|ttl_ms: i64| ttl_ms.max(1))
        .map_err(|_| CsrfTokenStoreError::RetentionOverflow)
}

/// In-memory CSRF token store for server-rendered form flows.
/// Each token is single-use and expires after a short TTL.
pub struct CsrfTokenStore {
    pub(super) backend: CsrfTokenBackend,
    pub(super) ttl: Duration,
}

pub(super) enum CsrfTokenBackend {
    #[cfg(test)]
    InMemory {
        tokens: RwLock<HashMap<String, SystemTime>>,
    },
    Redis(RedisCsrfTokenStore),
}

pub(super) struct RedisCsrfTokenStore {
    client: redis::Client,
    namespace: Arc<str>,
}

#[derive(Debug, Error)]
pub enum CsrfTokenStoreError {
    #[error("CSRF token store backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("CSRF token TTL cannot be represented")]
    RetentionOverflow,
}

impl CsrfTokenStore {
    #[cfg(test)]
    fn new_process_local() -> Self {
        Self {
            backend: CsrfTokenBackend::InMemory {
                tokens: RwLock::new(HashMap::new()),
            },
            ttl: Duration::from_secs(CSRF_TOKEN_TTL_SECS),
        }
    }

    /// Create a process-local CSRF token store for tests.
    ///
    /// Production code should use [`Self::try_from_shared_store_env`] so shared runtime state is
    /// required.
    #[doc(hidden)]
    #[cfg(test)]
    #[must_use]
    pub fn new_process_local_for_tests() -> Self {
        Self::new_process_local()
    }

    /// Build a CSRF token store from the Redis URL env var dedicated to this surface.
    ///
    /// `specific_url_key` is the only accepted Redis URL authority for this CSRF surface.
    pub fn try_from_shared_store_env(
        specific_url_key: &str,
        flow: &'static str,
        runtime_state_namespace: &RuntimeStateNamespace,
    ) -> Result<Self, ConfigError> {
        let url = require_shared_runtime_store_url("CSRF token store", specific_url_key)?;
        let redis_namespace = runtime_state_namespace.flow_namespace("csrf", flow);
        let backend =
            RedisCsrfTokenStore::new(url.as_str(), redis_namespace.clone()).map_err(|err| {
                ConfigError::InvalidValue {
                    key: url.env_key().to_string(),
                    value: "[redacted]".to_string(),
                    reason: err.to_string(),
                }
            })?;
        tracing::info!(flow, namespace = %redis_namespace, "CSRF token store backend: redis");
        Ok(Self {
            backend: CsrfTokenBackend::Redis(backend),
            ttl: Duration::from_secs(CSRF_TOKEN_TTL_SECS),
        })
    }

    /// Generate and store a new CSRF token for tests. Returns the raw token.
    #[cfg(test)]
    pub fn generate(&self) -> String {
        self.try_generate()
            .expect("test CSRF token generation should succeed")
    }

    /// Generate and store a new CSRF token.
    ///
    /// # Errors
    ///
    /// Returns [`CsrfTokenStoreError`] if the backend cannot retain the token.
    pub fn try_generate(&self) -> Result<String, CsrfTokenStoreError> {
        (0..CSRF_TOKEN_GENERATION_ATTEMPTS)
            .find_map(|_| {
                let token = match generate_csrf_token() {
                    Ok(token) => token,
                    Err(err) => return Some(Err(err)),
                };
                match self.try_insert(&token) {
                    Ok(true) => Some(Ok(token)),
                    Ok(false) => None,
                    Err(err) => Some(Err(err)),
                }
            })
            .unwrap_or_else(|| {
                Err(CsrfTokenStoreError::BackendUnavailable(
                    "CSRF token allocation exhausted".to_string(),
                ))
            })
    }

    pub async fn try_generate_async(self: Arc<Self>) -> Result<String, CsrfTokenStoreError> {
        tokio::task::spawn_blocking(move || self.try_generate())
            .await
            .map_err(|err| {
                CsrfTokenStoreError::BackendUnavailable(format!(
                    "CSRF token store worker failed: {err}"
                ))
            })?
    }

    fn try_insert(&self, token: &str) -> Result<bool, CsrfTokenStoreError> {
        match &self.backend {
            #[cfg(test)]
            CsrfTokenBackend::InMemory { tokens } => {
                let Some(expires_at) = SystemTime::now().checked_add(self.ttl) else {
                    return Err(CsrfTokenStoreError::RetentionOverflow);
                };
                let mut map = write_lock(tokens, "csrf_insert")
                    .map_err(CsrfTokenStoreError::BackendUnavailable)?;
                if map.contains_key(token) {
                    return Ok(false);
                }
                map.insert(token.to_string(), expires_at);
                Ok(true)
            }
            CsrfTokenBackend::Redis(store) => store.insert(token, self.ttl),
        }
    }

    /// Validate and consume a CSRF token (single-use).
    ///
    /// # Errors
    ///
    /// Returns [`CsrfTokenStoreError`] if the shared backend cannot determine
    /// whether the token exists.
    pub fn try_validate(&self, token: &str) -> Result<bool, CsrfTokenStoreError> {
        match &self.backend {
            #[cfg(test)]
            CsrfTokenBackend::InMemory { tokens } => {
                let mut map = write_lock(tokens, "validate_csrf")
                    .map_err(CsrfTokenStoreError::BackendUnavailable)?;
                match map.remove(token) {
                    Some(expires_at) => Ok(SystemTime::now() < expires_at),
                    None => Ok(false),
                }
            }
            CsrfTokenBackend::Redis(store) => store.validate(token),
        }
    }

    pub async fn try_validate_async(
        self: Arc<Self>,
        token: String,
    ) -> Result<bool, CsrfTokenStoreError> {
        tokio::task::spawn_blocking(move || self.try_validate(&token))
            .await
            .map_err(|err| {
                CsrfTokenStoreError::BackendUnavailable(format!(
                    "CSRF token store worker failed: {err}"
                ))
            })?
    }

    /// Clean up expired CSRF tokens.
    pub fn try_cleanup_expired(&self) -> Result<(), CsrfTokenStoreError> {
        match &self.backend {
            #[cfg(test)]
            CsrfTokenBackend::InMemory { tokens } => {
                let now = SystemTime::now();
                let mut map = write_lock(tokens, "cleanup_csrf")
                    .map_err(CsrfTokenStoreError::BackendUnavailable)?;
                map.retain(|_, expires_at| now < *expires_at);
                Ok(())
            }
            CsrfTokenBackend::Redis(_) => Ok(()),
        }
    }

    /// Clean up expired CSRF tokens for tests.
    #[cfg(test)]
    pub fn cleanup_expired(&self) {
        self.try_cleanup_expired()
            .expect("test CSRF token cleanup should succeed");
    }
}

impl RedisCsrfTokenStore {
    pub(super) fn new(
        url: &str,
        namespace: impl Into<Arc<str>>,
    ) -> Result<Self, CsrfTokenStoreError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                namespace: namespace.into(),
            })
            .map_err(|err| CsrfTokenStoreError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, CsrfTokenStoreError> {
        self.client
            .get_connection()
            .map_err(|err| CsrfTokenStoreError::BackendUnavailable(err.to_string()))
    }

    fn key(&self, token: &str) -> String {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"aegaeon:csrf:v1");
        hasher.update(&(self.namespace.len() as u64).to_be_bytes());
        hasher.update(self.namespace.as_bytes());
        hasher.update(&(token.len() as u64).to_be_bytes());
        hasher.update(token.as_bytes());
        format!(
            "{CSRF_REDIS_KEY_PREFIX}:{{{}}}:{}",
            self.namespace,
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        )
    }

    fn insert(&self, token: &str, ttl: Duration) -> Result<bool, CsrfTokenStoreError> {
        let ttl_ms = ttl_millis_i64(ttl)?;
        let result: redis::Value = redis::cmd("SET")
            .arg(self.key(token))
            .arg("1")
            .arg("NX")
            .arg("PX")
            .arg(ttl_ms)
            .query(&mut self.connection()?)
            .map_err(|err| CsrfTokenStoreError::BackendUnavailable(err.to_string()))?;
        match result {
            redis::Value::Okay => Ok(true),
            redis::Value::Nil => Ok(false),
            other => Err(CsrfTokenStoreError::BackendUnavailable(format!(
                "unexpected Redis SET response: {other:?}"
            ))),
        }
    }

    fn validate(&self, token: &str) -> Result<bool, CsrfTokenStoreError> {
        redis::Script::new(VALIDATE_TOKEN_SCRIPT)
            .key(self.key(token))
            .invoke::<i64>(&mut self.connection()?)
            .map(|value| value == 1)
            .map_err(|err| CsrfTokenStoreError::BackendUnavailable(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    fn referenced_indexes(script: &str, prefix: &str) -> Vec<usize> {
        let marker = format!("{prefix}[");
        script
            .match_indices(&marker)
            .filter_map(|(offset, _)| {
                let start = offset + marker.len();
                let digits: String = script[start..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect();
                digits.parse::<usize>().ok()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn expected_indexes(len: usize) -> Vec<usize> {
        (1..=len).collect()
    }

    fn invocation_body<'a>(source: &'a str, name: &str, invoke_marker: &str) -> &'a str {
        let start = source
            .find(name)
            .expect("script invocation function should exist");
        let rest = &source[start..];
        let end = rest
            .find(invoke_marker)
            .expect("script invocation should end with Redis invoke");
        &rest[..end]
    }

    fn assert_script_contract(script: &str, key_count: usize, arg_count: usize, body: &str) {
        assert_eq!(
            referenced_indexes(script, "KEYS"),
            expected_indexes(key_count)
        );
        assert_eq!(
            referenced_indexes(script, "ARGV"),
            expected_indexes(arg_count)
        );
        assert_eq!(body.matches(".key(self.key(token))").count(), key_count);
        assert_eq!(body.matches(".arg(").count(), arg_count);
    }

    #[test]
    fn validate_token_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("csrf.rs");
        let body = invocation_body(source, "fn validate(&self, token: &str)", ".invoke::<i64>(");
        assert_script_contract(
            super::VALIDATE_TOKEN_SCRIPT,
            super::VALIDATE_TOKEN_SCRIPT_KEY_COUNT,
            super::VALIDATE_TOKEN_SCRIPT_ARG_COUNT,
            body,
        );
    }
}
