use super::super::redis_support::{access_token_expires_at, system_time_epoch_secs};
use super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

impl RedisTokenStoreBackend {
    pub(super) fn expired_index_members(
        &self,
        conn: &mut redis::Connection,
        key: String,
        now: SystemTime,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        redis::cmd("ZRANGEBYSCORE")
            .arg(key)
            .arg("-inf")
            .arg(system_time_epoch_secs(now))
            .query::<Vec<String>>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn subject_access_tokens(
        &self,
        conn: &mut redis::Connection,
        subject: &str,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        self.subject_tokens(conn, self.keyspace.subject_access_key(subject))
    }

    pub(super) fn subject_refresh_tokens(
        &self,
        conn: &mut redis::Connection,
        subject: &str,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        self.subject_tokens(conn, self.keyspace.subject_refresh_key(subject))
    }

    pub(super) fn subject_bearer_tokens(
        &self,
        conn: &mut redis::Connection,
        subject: &str,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        self.subject_tokens(conn, self.keyspace.subject_bearer_key(subject))
    }

    fn subject_tokens(
        &self,
        conn: &mut redis::Connection,
        key: String,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        redis::cmd("SMEMBERS")
            .arg(key)
            .query::<Vec<String>>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn index_access_cmd(&self, pipe: &mut redis::Pipeline, token: &AccessToken) {
        pipe.cmd("SADD")
            .arg(self.keyspace.subject_access_key(&token.user_id))
            .arg(&token.token)
            .ignore();
        pipe.cmd("ZADD")
            .arg(self.keyspace.expiry_access_key())
            .arg(system_time_epoch_secs(access_token_expires_at(token)))
            .arg(&token.token)
            .ignore();
    }

    pub(super) fn deindex_access_cmd(
        &self,
        pipe: &mut redis::Pipeline,
        token: &str,
        record: Option<&AccessToken>,
    ) {
        if let Some(record) = record {
            pipe.cmd("SREM")
                .arg(self.keyspace.subject_access_key(&record.user_id))
                .arg(token)
                .ignore();
        }
        pipe.cmd("ZREM")
            .arg(self.keyspace.expiry_access_key())
            .arg(token)
            .ignore();
    }

    pub(super) fn index_refresh_cmd(&self, pipe: &mut redis::Pipeline, token: &RefreshToken) {
        pipe.cmd("SADD")
            .arg(self.keyspace.subject_refresh_key(&token.user_id))
            .arg(&token.token)
            .ignore();
        pipe.cmd("ZADD")
            .arg(self.keyspace.expiry_refresh_key())
            .arg(system_time_epoch_secs(token.expires_at))
            .arg(&token.token)
            .ignore();
    }

    pub(super) fn deindex_refresh_cmd(
        &self,
        pipe: &mut redis::Pipeline,
        token: &str,
        record: Option<&RefreshToken>,
    ) {
        if let Some(record) = record {
            pipe.cmd("SREM")
                .arg(self.keyspace.subject_refresh_key(&record.user_id))
                .arg(token)
                .ignore();
        }
        pipe.cmd("ZREM")
            .arg(self.keyspace.expiry_refresh_key())
            .arg(token)
            .ignore();
    }

    pub(super) fn index_bearer_cmd(&self, pipe: &mut redis::Pipeline, meta: &BearerTokenMeta) {
        pipe.cmd("SADD")
            .arg(self.keyspace.subject_bearer_key(&meta.user_id))
            .arg(&meta.token_id)
            .ignore();
        pipe.cmd("ZADD")
            .arg(self.keyspace.expiry_bearer_key())
            .arg(system_time_epoch_secs(meta.expires_at))
            .arg(&meta.token_id)
            .ignore();
    }

    pub(super) fn deindex_bearer_cmd(
        &self,
        pipe: &mut redis::Pipeline,
        token: &str,
        record: Option<&BearerTokenMeta>,
    ) {
        if let Some(record) = record {
            pipe.cmd("SREM")
                .arg(self.keyspace.subject_bearer_key(&record.user_id))
                .arg(token)
                .ignore();
        }
        pipe.cmd("ZREM")
            .arg(self.keyspace.expiry_bearer_key())
            .arg(token)
            .ignore();
    }

    pub(super) fn index_revoked_cmd(
        &self,
        pipe: &mut redis::Pipeline,
        token: &str,
        expires_at: SystemTime,
    ) {
        pipe.cmd("ZADD")
            .arg(self.keyspace.expiry_revoked_key())
            .arg(system_time_epoch_secs(expires_at))
            .arg(token)
            .ignore();
    }

    pub(super) fn deindex_revoked_cmd(&self, pipe: &mut redis::Pipeline, token: &str) {
        pipe.cmd("ZREM")
            .arg(self.keyspace.expiry_revoked_key())
            .arg(token)
            .ignore();
    }
}
