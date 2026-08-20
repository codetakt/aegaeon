#[cfg(test)]
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::scripts::{
    consume_code_script, invoke_store_code_if_absent, release_lock_if_owner_script,
    StoreCodeIfAbsentArgs, StoreCodeIfAbsentKeys,
};
#[cfg(test)]
use super::AuthCodeSnapshot;
use super::{
    remaining_ttl, ttl_millis_i64, AuthCodeBackend, AuthCodeExchangeLock,
    AuthCodeRedisCommitContext, AuthCodeStorageError, AuthorizationCode,
    AuthorizationCodeOneTimeInputCommit, StoreCodeError, AUTH_CODE_EXCHANGE_LOCK_RETRIES,
    AUTH_CODE_EXCHANGE_LOCK_RETRY_DELAY_MS, AUTH_CODE_EXCHANGE_LOCK_TTL_MS,
};
use crate::config::{
    redis_store_urls_reference_same_endpoint, RuntimeRedisAtomicGroup, RuntimeStateNamespace,
};
use std::sync::Arc;
use tracing::warn;

mod keyspace;
use keyspace::RedisAuthCodeKeyspace;

#[derive(Clone)]
pub(in crate::authcode) struct RedisAuthCodeBackend {
    client: redis::Client,
    url: Arc<str>,
    state_nonce_ttl: Duration,
    keyspace: RedisAuthCodeKeyspace,
}

impl RedisAuthCodeBackend {
    pub(in crate::authcode) fn new(
        url: &str,
        state_nonce_ttl: Duration,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, AuthCodeStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: Arc::from(url.to_string().into_boxed_str()),
                state_nonce_ttl,
                keyspace: RedisAuthCodeKeyspace::new(namespace.redis_atomic_group_prefix(
                    RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
                    "authcode",
                    "v2",
                )),
            })
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(in crate::authcode) fn new_for_tests(
        url: &str,
        state_nonce_ttl: Duration,
    ) -> Result<Self, AuthCodeStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: Arc::from(url.to_string().into_boxed_str()),
                state_nonce_ttl,
                keyspace: RedisAuthCodeKeyspace::for_tests(),
            })
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, AuthCodeStorageError> {
        self.client
            .get_connection()
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
    }

    fn acquire_exchange_lock_key(
        &self,
        conn: &mut redis::Connection,
        lock_key: &str,
        lock_token: &str,
    ) -> Result<bool, AuthCodeStorageError> {
        match redis::cmd("SET")
            .arg(lock_key)
            .arg(lock_token)
            .arg("NX")
            .arg("PX")
            .arg(AUTH_CODE_EXCHANGE_LOCK_TTL_MS)
            .query::<redis::Value>(conn)
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?
        {
            redis::Value::Okay => Ok(true),
            redis::Value::Nil => Ok(false),
            other => Err(AuthCodeStorageError::BackendUnavailable(format!(
                "unexpected Redis authorization-code exchange lock response: {other:?}"
            ))),
        }
    }

    pub(in crate::authcode) fn release_exchange_lock(&self, lock_key: &str, lock_token: &str) {
        let result = self.connection().and_then(|mut conn| {
            release_lock_if_owner_script()
                .key(lock_key)
                .arg(lock_token)
                .invoke::<i64>(&mut conn)
                .map(|_| ())
                .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
        });
        if let Err(err) = result {
            warn!(
                target: "authcode",
                error = %err,
                "failed to release Redis authorization-code exchange lock"
            );
        }
    }

    #[cfg(test)]
    fn scan_keys(
        conn: &mut redis::Connection,
        pattern: &str,
    ) -> Result<Vec<String>, AuthCodeStorageError> {
        let mut cursor = 0_u64;
        let mut keys = Vec::new();
        loop {
            let (next, mut page): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(128)
                .query(conn)
                .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?;
            keys.append(&mut page);
            cursor = next;
            if cursor == 0 {
                return Ok(keys);
            }
        }
    }

    fn epoch_millis() -> Result<u64, AuthCodeStorageError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?
            .as_millis()
            .try_into()
            .map_err(|_| AuthCodeStorageError::RetentionOverflow)
    }

    fn expires_at_epoch_millis(ttl: Duration) -> Result<u64, AuthCodeStorageError> {
        let now = Self::epoch_millis()?;
        let ttl_ms: u64 = ttl
            .as_millis()
            .try_into()
            .map_err(|_| AuthCodeStorageError::RetentionOverflow)?;
        now.checked_add(ttl_ms)
            .ok_or(AuthCodeStorageError::RetentionOverflow)
    }

    fn prune_index(
        conn: &mut redis::Connection,
        index_key: String,
    ) -> Result<(), AuthCodeStorageError> {
        redis::cmd("ZREMRANGEBYSCORE")
            .arg(index_key)
            .arg("-inf")
            .arg(Self::epoch_millis()?)
            .query::<usize>(conn)
            .map(|_| ())
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
    }

    fn validate_one_time_input_urls(
        &self,
        one_time_inputs: &AuthorizationCodeOneTimeInputCommit,
    ) -> Result<(), StoreCodeError> {
        if let Some(par) = one_time_inputs.par.as_ref() {
            if !redis_store_urls_reference_same_endpoint(par.url.as_ref(), self.url.as_ref()) {
                return Err(AuthCodeStorageError::BackendUnavailable(
                    "PAR request_uri store Redis URL must match authorization-code store Redis URL for atomic authorize commit".to_string(),
                )
                .into());
            }
        }
        if let Some(request_object_jti) = one_time_inputs.request_object_jti.as_ref() {
            if !redis_store_urls_reference_same_endpoint(
                request_object_jti.url.as_ref(),
                self.url.as_ref(),
            ) {
                return Err(AuthCodeStorageError::BackendUnavailable(
                    "Request Object jti replay store Redis URL must match authorization-code store Redis URL for atomic authorize commit".to_string(),
                )
                .into());
            }
        }
        Ok(())
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "owned inputs make the one-time authorization-code commit boundary explicit"
    )]
    fn store_code_with_one_time_inputs_inner(
        &self,
        code: AuthorizationCode,
        one_time_inputs: AuthorizationCodeOneTimeInputCommit,
    ) -> Result<String, StoreCodeError> {
        self.validate_one_time_input_urls(&one_time_inputs)?;
        let code_ttl = remaining_ttl(code.expires_at).ok_or(StoreCodeError::Expired)?;
        let code_key = self.keyspace.code(&code.code);
        let state_key = code.state.as_deref().map_or_else(
            || self.keyspace.placeholder("state"),
            |state| self.keyspace.state(state),
        );
        let nonce_key = code.nonce.as_deref().map_or_else(
            || self.keyspace.placeholder("nonce"),
            |nonce| self.keyspace.nonce(nonce),
        );
        let code_str = code.code.clone();
        let state_value = match &code.state {
            Some(state) => state.clone(),
            None => String::new(),
        };
        let nonce_value = match &code.nonce {
            Some(nonce) => nonce.clone(),
            None => String::new(),
        };
        let payload = serde_json::to_string(&code)
            .map_err(|err| AuthCodeStorageError::Serialize(err.to_string()))?;
        let marker_ttl_ms = ttl_millis_i64(self.state_nonce_ttl)?;
        let code_ttl_ms = ttl_millis_i64(code_ttl)?;
        let marker_expires_at_epoch_ms = Self::expires_at_epoch_millis(self.state_nonce_ttl)?;
        let placeholder = self.keyspace.placeholder("one-time");
        let par_request_key = one_time_inputs
            .par
            .as_ref()
            .map_or(placeholder.as_str(), |par| par.request_key.as_str());
        let par_reservation_key = one_time_inputs
            .par
            .as_ref()
            .map_or(placeholder.as_str(), |par| par.reservation_key.as_str());
        let par_expected_continuation = one_time_inputs
            .par
            .as_ref()
            .map_or("", |par| par.expected_continuation.as_str());
        let request_object_jti_key = one_time_inputs
            .request_object_jti
            .as_ref()
            .map_or(placeholder.as_str(), |jti| jti.key.as_str());
        let request_object_jti_ttl_ms = one_time_inputs
            .request_object_jti
            .as_ref()
            .map_or(1, |jti| jti.ttl_ms);
        let version_key = self.keyspace.version();
        let state_index_key = self.keyspace.state_index();
        let nonce_index_key = self.keyspace.nonce_index();

        let outcome = invoke_store_code_if_absent(
            &mut self.connection()?,
            StoreCodeIfAbsentKeys {
                code: code_key.as_str(),
                state: state_key.as_str(),
                nonce: nonce_key.as_str(),
                version: version_key.as_str(),
                state_index: state_index_key.as_str(),
                nonce_index: nonce_index_key.as_str(),
                par_request: par_request_key,
                par_reservation: par_reservation_key,
                request_object_jti: request_object_jti_key,
            },
            StoreCodeIfAbsentArgs {
                payload: payload.as_str(),
                marker_ttl_ms,
                code_ttl_ms,
                has_state: code.state.is_some(),
                has_nonce: code.nonce.is_some(),
                state_value: state_value.as_str(),
                nonce_value: nonce_value.as_str(),
                marker_expires_at_epoch_ms,
                has_par: one_time_inputs.par.is_some(),
                has_request_object_jti: one_time_inputs.request_object_jti.is_some(),
                request_object_jti_ttl_ms,
                par_expected_continuation,
            },
        )
        .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?;

        match outcome.as_str() {
            "ok" => Ok(code_str),
            "state" => Err(StoreCodeError::StateUsed),
            "nonce" => Err(StoreCodeError::NonceUsed),
            "code" => Err(StoreCodeError::CodeCollision),
            "par" => Err(StoreCodeError::PushedAuthorizationRequestMissing),
            "request_object_jti" => Err(StoreCodeError::RequestObjectJtiReplay),
            other => Err(AuthCodeStorageError::BackendUnavailable(format!(
                "unexpected Redis script response: {other}"
            ))
            .into()),
        }
    }
}

impl AuthCodeBackend for RedisAuthCodeBackend {
    fn redis_commit_context(&self, code: &str) -> Option<AuthCodeRedisCommitContext> {
        Some(AuthCodeRedisCommitContext {
            url: Arc::clone(&self.url),
            code_key: self.keyspace.code(code),
            version_key: self.keyspace.version(),
        })
    }

    fn acquire_exchange_lock(
        &self,
        code: &str,
    ) -> Result<AuthCodeExchangeLock, AuthCodeStorageError> {
        let lock_key = self.keyspace.exchange_lock(code);
        let lock_token = aegaeon_crypto::rand::random_base64url(24);
        let mut conn = self.connection()?;
        for _ in 0..AUTH_CODE_EXCHANGE_LOCK_RETRIES {
            if self.acquire_exchange_lock_key(&mut conn, &lock_key, &lock_token)? {
                return Ok(AuthCodeExchangeLock::redis(
                    self.clone(),
                    lock_key,
                    lock_token,
                ));
            }
            std::thread::sleep(Duration::from_millis(
                AUTH_CODE_EXCHANGE_LOCK_RETRY_DELAY_MS,
            ));
        }
        Err(AuthCodeStorageError::BackendUnavailable(
            "timed out acquiring Redis authorization-code exchange lock".to_string(),
        ))
    }

    #[cfg(test)]
    fn snapshot(&self) -> Result<AuthCodeSnapshot, AuthCodeStorageError> {
        let mut conn = self.connection()?;
        let code_keys = Self::scan_keys(&mut conn, &self.keyspace.code_scan_pattern())?;
        let state_keys = Self::scan_keys(&mut conn, &self.keyspace.state_scan_pattern())?;
        let nonce_keys = Self::scan_keys(&mut conn, &self.keyspace.nonce_scan_pattern())?;

        let mut codes = HashMap::new();
        for key in code_keys {
            if let Some(payload) = redis::cmd("GET")
                .arg(&key)
                .query::<Option<String>>(&mut conn)
                .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?
            {
                let code = serde_json::from_str::<AuthorizationCode>(&payload)
                    .map_err(|err| AuthCodeStorageError::Serialize(err.to_string()))?;
                if !code.used && !code.is_expired() {
                    codes.insert(code.code.clone(), code);
                }
            }
        }

        let used_states = read_marker_values(&mut conn, state_keys)?;
        let used_nonces = read_marker_values(&mut conn, nonce_keys)?;
        let version = redis::cmd("GET")
            .arg(self.keyspace.version())
            .query::<Option<u64>>(&mut conn)
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?
            .unwrap_or(0);

        Ok(AuthCodeSnapshot {
            codes,
            used_states,
            used_nonces,
            version,
        })
    }

    fn get_code(&self, code_str: &str) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        let mut conn = self.connection()?;
        let payload = redis::cmd("GET")
            .arg(self.keyspace.code(code_str))
            .query::<Option<String>>(&mut conn)
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?;
        payload
            .map(|payload| {
                serde_json::from_str::<AuthorizationCode>(&payload)
                    .map_err(|err| AuthCodeStorageError::Serialize(err.to_string()))
                    .map(|code| (!code.used && !code.is_expired()).then_some(code))
            })
            .transpose()
            .map(Option::flatten)
    }

    fn store_code(&self, code: AuthorizationCode) -> Result<String, StoreCodeError> {
        self.store_code_with_one_time_inputs_inner(
            code,
            AuthorizationCodeOneTimeInputCommit::default(),
        )
    }

    fn store_code_with_one_time_inputs(
        &self,
        code: AuthorizationCode,
        one_time_inputs: AuthorizationCodeOneTimeInputCommit,
    ) -> Result<String, StoreCodeError> {
        self.store_code_with_one_time_inputs_inner(code, one_time_inputs)
    }

    fn use_code(&self, code_str: &str) -> Result<Option<AuthorizationCode>, AuthCodeStorageError> {
        let payload = consume_code_script()
            .key(self.keyspace.code(code_str))
            .key(self.keyspace.version())
            .invoke::<Option<String>>(&mut self.connection()?)
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?;
        payload
            .map(|payload| {
                serde_json::from_str::<AuthorizationCode>(&payload)
                    .map_err(|err| AuthCodeStorageError::Serialize(err.to_string()))
                    .map(|code| (!code.used && !code.is_expired()).then_some(code))
            })
            .transpose()
            .map(Option::flatten)
    }

    fn cleanup_expired(&self) -> Result<(), AuthCodeStorageError> {
        let mut conn = self.connection()?;
        Self::prune_index(&mut conn, self.keyspace.state_index())?;
        Self::prune_index(&mut conn, self.keyspace.nonce_index())
    }

    fn state_count(&self) -> Result<usize, AuthCodeStorageError> {
        let mut conn = self.connection()?;
        let state_index_key = self.keyspace.state_index();
        Self::prune_index(&mut conn, state_index_key.clone())?;
        redis::cmd("ZCARD")
            .arg(state_index_key)
            .query::<usize>(&mut conn)
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
    }

    fn nonce_count(&self) -> Result<usize, AuthCodeStorageError> {
        let mut conn = self.connection()?;
        let nonce_index_key = self.keyspace.nonce_index();
        Self::prune_index(&mut conn, nonce_index_key.clone())?;
        redis::cmd("ZCARD")
            .arg(nonce_index_key)
            .query::<usize>(&mut conn)
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))
    }
}

#[cfg(test)]
fn read_marker_values(
    conn: &mut redis::Connection,
    keys: Vec<String>,
) -> Result<HashSet<String>, AuthCodeStorageError> {
    let mut values = HashSet::new();
    for key in keys {
        if let Some(value) = redis::cmd("GET")
            .arg(key)
            .query::<Option<String>>(conn)
            .map_err(|err| AuthCodeStorageError::BackendUnavailable(err.to_string()))?
        {
            values.insert(value);
        }
    }
    Ok(values)
}
