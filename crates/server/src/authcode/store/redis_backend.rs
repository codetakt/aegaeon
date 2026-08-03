mod cleanup;
mod collision;
mod commit_result;
mod indexes;
mod reads;
mod revocation;
mod rotation;
mod scripts;
mod snapshot;
mod writes;

use super::redis_support::{
    RedisTokenStoreKeyspace, TOKEN_STORE_REDIS_LOCK_RETRIES, TOKEN_STORE_REDIS_LOCK_RETRY_DELAY_MS,
    TOKEN_STORE_REDIS_LOCK_TTL_MS,
};
use super::TokenStoreStorageError;
use crate::config::{RuntimeRedisAtomicGroup, RuntimeStateNamespace};
use scripts::release_lock_if_owner_script;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

#[derive(Clone)]
pub(super) struct RedisTokenStoreBackend {
    client: redis::Client,
    url: Arc<str>,
    keyspace: RedisTokenStoreKeyspace,
}

impl RedisTokenStoreBackend {
    pub(super) fn new(
        url: &str,
        namespace: &RuntimeStateNamespace,
    ) -> Result<Self, TokenStoreStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: Arc::from(url.to_string().into_boxed_str()),
                keyspace: RedisTokenStoreKeyspace::new(namespace.redis_atomic_group_prefix(
                    RuntimeRedisAtomicGroup::AuthorizationCodeGrant,
                    "token-store",
                    "v3",
                )),
            })
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
    pub(super) fn new_for_tests(url: &str) -> Result<Self, TokenStoreStorageError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                url: Arc::from(url.to_string().into_boxed_str()),
                keyspace: RedisTokenStoreKeyspace::new("token-store:v3:{tokens}"),
            })
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn connection(&self) -> Result<redis::Connection, TokenStoreStorageError> {
        self.client
            .get_connection()
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn acquire_lock(
        &self,
        conn: &mut redis::Connection,
        lock_token: &str,
    ) -> Result<bool, TokenStoreStorageError> {
        match redis::cmd("SET")
            .arg(self.keyspace.lock_key())
            .arg(lock_token)
            .arg("NX")
            .arg("PX")
            .arg(TOKEN_STORE_REDIS_LOCK_TTL_MS)
            .query::<redis::Value>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))?
        {
            redis::Value::Okay => Ok(true),
            redis::Value::Nil => Ok(false),
            other => Err(TokenStoreStorageError::BackendUnavailable(format!(
                "unexpected Redis lock response: {other:?}"
            ))),
        }
    }

    pub(super) fn release_lock(&self, conn: &mut redis::Connection, lock_token: &str) {
        let result = release_lock_if_owner_script()
            .key(self.keyspace.lock_key())
            .arg(lock_token)
            .invoke::<i64>(conn);
        if let Err(err) = result {
            warn!(target: "tokens", error=%err, "failed to release redis token store lock");
        }
    }

    pub(super) fn acquire_operation_lock(
        &self,
        conn: &mut redis::Connection,
        operation: &'static str,
    ) -> Result<String, TokenStoreStorageError> {
        let lock_token = aegaeon_crypto::rand::random_base64url(24);
        for _ in 0..TOKEN_STORE_REDIS_LOCK_RETRIES {
            if self.acquire_lock(conn, &lock_token)? {
                return Ok(lock_token);
            }
            std::thread::sleep(Duration::from_millis(TOKEN_STORE_REDIS_LOCK_RETRY_DELAY_MS));
        }
        Err(TokenStoreStorageError::BackendUnavailable(format!(
            "timed out acquiring Redis token store lock for {operation}"
        )))
    }

    pub(super) fn with_lock<R>(
        &self,
        operation: &'static str,
        f: impl FnOnce(&mut redis::Connection) -> Result<R, TokenStoreStorageError>,
    ) -> Result<R, TokenStoreStorageError> {
        let mut conn = self.connection()?;
        let lock_token = self.acquire_operation_lock(&mut conn, operation)?;
        let result = f(&mut conn);
        self.release_lock(&mut conn, &lock_token);
        result
    }
}
