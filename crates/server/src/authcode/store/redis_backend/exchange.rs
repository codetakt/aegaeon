use super::RedisTokenStoreBackend;
use crate::authcode::store::exchange_commit::validate_exchange_subject;
use crate::authcode::store::redis_support::{
    decode_redis_json, encode_redis_json, system_time_epoch_secs, RedisRefreshChildrenRecord,
};
use crate::authcode::store::{exchange_commit::validate_exchange_commit, ExchangeCommitError};
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::SystemTime;

// The lock owner fences expired leases; exact payloads and version fence all validation reads.
// Redis TIME rechecks the deadlines at the same linearization point as publication.
const COMMIT: &str = r"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 'lost_lock' end
for i=3,5 do
  if redis.call('GET', KEYS[i]) ~= ARGV[i] then return 'stale_subject' end
end
if redis.call('EXISTS', KEYS[6], KEYS[7], KEYS[15]) ~= 0 then return 'revoked' end
if (redis.call('GET', KEYS[2]) or '0') ~= ARGV[2] then return 'stale_version' end
if redis.call('EXISTS', KEYS[8], KEYS[9]) ~= 0 then return 'collision' end
local now = tonumber(redis.call('TIME')[1])
if now >= tonumber(ARGV[13]) then return 'expired_root' end
if now >= tonumber(ARGV[6]) or now >= tonumber(ARGV[7]) or now >= tonumber(ARGV[8]) then return 'expired' end
-- Check index types before writing: Redis scripts do not roll back runtime errors.
for i=10,12 do
  local expected = 'set'
  if i == 10 then expected = 'string' end
  local actual = redis.call('TYPE', KEYS[i]).ok
  if actual ~= 'none' and actual ~= expected then return 'index_type' end
end
for i=13,14 do
  local actual = redis.call('TYPE', KEYS[i]).ok
  if actual ~= 'none' and actual ~= 'zset' then return 'index_type' end
end
redis.call('SET', KEYS[8], ARGV[9])
redis.call('SET', KEYS[9], ARGV[10])
if ARGV[14] == '1' then redis.call('SET', KEYS[10], ARGV[11]) end
redis.call('SADD', KEYS[11], ARGV[12])
redis.call('SADD', KEYS[12], ARGV[12])
redis.call('ZADD', KEYS[13], ARGV[8], ARGV[12])
redis.call('ZADD', KEYS[14], ARGV[8], ARGV[12])
redis.call('INCR', KEYS[2])
return 'ok'
";

#[expect(
    clippy::needless_pass_by_value,
    reason = "map_err passes its owned error to this adapter"
)]
fn backend(error: impl ToString) -> ExchangeCommitError {
    ExchangeCommitError::Storage(error.to_string())
}
fn invalid(reason: impl Into<String>) -> ExchangeCommitError {
    ExchangeCommitError::Rejected(reason.into())
}
fn raw(conn: &mut redis::Connection, key: String) -> Result<String, ExchangeCommitError> {
    redis::cmd("GET")
        .arg(key)
        .query::<Option<String>>(conn)
        .map_err(backend)?
        .ok_or_else(|| invalid("missing exchange lineage record"))
}

impl RedisTokenStoreBackend {
    pub(in crate::authcode::store) fn store_exchanged_access(
        &self,
        access: &AccessToken,
        output: &BearerTokenMeta,
        expected: &BearerTokenMeta,
    ) -> Result<(), ExchangeCommitError> {
        let mut conn = self.connection()?;
        let lock = self.acquire_operation_lock(&mut conn, "store_exchanged_access")?;
        let result = self.commit_exchange(&mut conn, &lock, access, output, expected);
        self.release_lock(&mut conn, &lock);
        result
    }

    fn commit_exchange(
        &self,
        conn: &mut redis::Connection,
        lock: &str,
        access: &AccessToken,
        output: &BearerTokenMeta,
        expected: &BearerTokenMeta,
    ) -> Result<(), ExchangeCommitError> {
        let parent_id = output.refresh_parent.as_deref();
        let version = redis::cmd("GET")
            .arg(self.keyspace.version_key())
            .query::<Option<u64>>(conn)
            .map_err(backend)?
            .unwrap_or(0);
        if version >= i64::MAX as u64 {
            return Err(backend("token store version exhausted"));
        }
        let subject_raw = raw(conn, self.keyspace.bearer_key(&expected.token_id))?;
        let access_raw = raw(conn, self.keyspace.access_key(&expected.token_id))?;
        // Without a refresh parent, compare the already-read access record twice.
        // This avoids a synthetic Redis key whose state could affect another grant.
        let parent_key = parent_id.map_or_else(
            || self.keyspace.access_key(&expected.token_id),
            |id| self.keyspace.refresh_key(id),
        );
        let parent_raw = if parent_id.is_some() {
            raw(conn, parent_key.clone())?
        } else {
            access_raw.clone()
        };
        let parent: Option<RefreshToken> = if parent_id.is_some() {
            Some(decode_redis_json(&parent_raw)?)
        } else {
            None
        };
        let subject: BearerTokenMeta = decode_redis_json(&subject_raw)?;
        let subject_access: AccessToken = decode_redis_json(&access_raw)?;
        validate_exchange_subject(&subject_access, &subject).map_err(invalid)?;
        if subject_access.is_expired()
            || serde_json::to_value(&subject).map_err(backend)?
                != serde_json::to_value(expected).map_err(backend)?
        {
            return Err(invalid("exchange subject has changed"));
        }
        validate_exchange_commit(access, output, &subject, parent.as_ref(), SystemTime::now())
            .map_err(invalid)?;
        let retained = output.refresh_parent.as_deref();
        let children = if let Some(id) = retained {
            let mut children = self.refresh_children(conn, id)?;
            if children.len()
                >= super::super::redis_support::MAX_REFRESH_FAMILY_REVOCATION_CHILD_TOKENS
            {
                return Err(backend("refresh lineage child limit"));
            }
            children.insert(access.token.clone());
            encode_redis_json(&RedisRefreshChildrenRecord {
                refresh_token: id.into(),
                access_tokens: children,
            })?
        } else {
            String::new()
        };
        let root = access.exchange_root.as_ref();
        let keys = [
            self.keyspace.lock_key(),
            self.keyspace.version_key(),
            parent_key,
            self.keyspace.bearer_key(&expected.token_id),
            self.keyspace.access_key(&expected.token_id),
            self.keyspace
                .revoked_key(parent_id.unwrap_or(&expected.token_id)),
            self.keyspace.revoked_key(&expected.token_id),
            self.keyspace.access_key(&access.token),
            self.keyspace.bearer_key(&output.token_id),
            retained.map_or_else(
                || self.keyspace.access_key(&expected.token_id),
                |id| self.keyspace.refresh_children_key(id),
            ),
            self.keyspace.subject_access_key(&access.user_id),
            self.keyspace.subject_bearer_key(&access.user_id),
            self.keyspace.expiry_access_key(),
            self.keyspace.expiry_bearer_key(),
            self.keyspace
                .revoked_key(root.map_or(expected.token_id.as_str(), |root| root.id.as_str())),
        ];
        let outcome: String = redis::Script::new(COMMIT)
            .key(&keys)
            .arg(lock)
            .arg(version)
            .arg(parent_raw)
            .arg(subject_raw)
            .arg(access_raw)
            .arg(system_time_epoch_secs(
                parent
                    .as_ref()
                    .map_or(subject.expires_at, |parent| parent.expires_at),
            ))
            .arg(system_time_epoch_secs(subject.expires_at))
            .arg(system_time_epoch_secs(output.expires_at))
            .arg(encode_redis_json(access)?)
            .arg(encode_redis_json(output)?)
            .arg(children)
            .arg(&access.token)
            .arg(system_time_epoch_secs(
                root.map_or(subject.expires_at, |root| root.expires_at),
            ))
            .arg(if retained.is_some() { "1" } else { "0" })
            .invoke(conn)
            .map_err(backend)?;
        interpret_commit_result(outcome)
    }
}

fn interpret_commit_result(outcome: String) -> Result<(), ExchangeCommitError> {
    match outcome.as_str() {
        "ok" => Ok(()),
        "revoked" | "expired" | "expired_root" | "stale_subject" => Err(invalid(outcome)),
        _ => Err(backend(format!("exchange commit failed: {outcome}"))),
    }
}

#[cfg(test)]
mod tests;
