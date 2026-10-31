#[cfg(test)]
use super::super::redis_support::access_token_expires_at;
use super::super::redis_support::system_time_epoch_secs;
use super::RedisTokenStoreBackend;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

// Stale-index cleanup may discard only the requested index membership. The authority
// record can be created or replaced after it was observed, even under a lease.
const PRUNE_OBSERVED_SUBJECT_MEMBER: &str = r#"
local current = redis.call("GET", KEYS[1])
if ARGV[1] == "absent" then
  if current then return 0 end
elseif ARGV[1] == "present" then
  if current ~= ARGV[2] then return 0 end
else
  return 0
end
return redis.call("SREM", KEYS[2], ARGV[3])
"#;

impl RedisTokenStoreBackend {
    pub(super) fn expired_index_members(
        &self,
        conn: &mut impl redis::ConnectionLike,
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
        conn: &mut impl redis::ConnectionLike,
        subject: &str,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        self.subject_tokens(conn, self.keyspace.subject_access_key(subject))
    }

    pub(super) fn subject_refresh_tokens(
        &self,
        conn: &mut impl redis::ConnectionLike,
        subject: &str,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        self.subject_tokens(conn, self.keyspace.subject_refresh_key(subject))
    }

    pub(super) fn subject_bearer_tokens(
        &self,
        conn: &mut impl redis::ConnectionLike,
        subject: &str,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        self.subject_tokens(conn, self.keyspace.subject_bearer_key(subject))
    }

    fn subject_tokens(
        &self,
        conn: &mut impl redis::ConnectionLike,
        key: String,
    ) -> Result<Vec<String>, TokenStoreStorageError> {
        redis::cmd("SMEMBERS")
            .arg(key)
            .query::<Vec<String>>(conn)
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    pub(super) fn prune_missing_subject_member(
        &self,
        conn: &mut impl redis::ConnectionLike,
        record_key: &str,
        subject_key: &str,
        token: &str,
    ) -> Result<(), TokenStoreStorageError> {
        self.prune_observed_subject_member(conn, record_key, subject_key, token, None)
    }

    pub(super) fn prune_observed_subject_member(
        &self,
        conn: &mut impl redis::ConnectionLike,
        record_key: &str,
        subject_key: &str,
        token: &str,
        observed_raw: Option<&str>,
    ) -> Result<(), TokenStoreStorageError> {
        redis::Script::new(PRUNE_OBSERVED_SUBJECT_MEMBER)
            .key(record_key)
            .key(subject_key)
            .arg(if observed_raw.is_some() {
                "present"
            } else {
                "absent"
            })
            .arg(observed_raw.map_or("", |raw| raw))
            .arg(token)
            .invoke::<usize>(conn)
            .map(|_| ())
            .map_err(|err| TokenStoreStorageError::BackendUnavailable(err.to_string()))
    }

    #[cfg(test)]
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

    #[cfg(test)]
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

    #[cfg(test)]
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

#[cfg(test)]
impl RedisTokenStoreBackend {
    pub(crate) fn prune_inventory_observation_for_tests(
        &self,
        record_key: &str,
        subject_key: &str,
        token: &str,
        observed: Option<&str>,
    ) {
        self.prune_observed_subject_member(
            &mut self.connection().unwrap(),
            record_key,
            subject_key,
            token,
            observed,
        )
        .unwrap();
    }
}

#[cfg(test)]
impl RedisTokenStoreBackend {
    pub(crate) fn prune_missing_subject_member_for_tests(
        &self,
        record_key: &str,
        subject_key: &str,
        token: &str,
    ) {
        self.prune_missing_subject_member(
            &mut self.connection().unwrap(),
            record_key,
            subject_key,
            token,
        )
        .unwrap();
    }
}
