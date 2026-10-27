use super::super::refresh_grants::GrantCommit;
use super::super::RedisTokenStoreBackend;
use crate::authcode::store::redis_support::{
    access_token_expires_at, encode_redis_json, system_time_epoch_secs,
};
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{AccessToken, BearerTokenMeta, RefreshToken};
use std::time::UNIX_EPOCH;

const COMMIT: &str = r"
if redis.call('EXISTS', KEYS[2], KEYS[3]) ~= 0 then return 'token_collision' end
if ARGV[1] == '1' and redis.call('EXISTS', KEYS[4], KEYS[5]) ~= 0 then return 'token_collision' end
if ARGV[1] == '2' then
  if redis.call('GET', KEYS[4]) ~= ARGV[11] or redis.call('EXISTS', KEYS[12]) ~= 0 then return 'invalid' end
  local time = redis.call('TIME')
  if decimal_ge(time[1], ARGV[12]) and (time[1] ~= ARGV[12] or tonumber(time[2])*1000 >= tonumber(ARGV[13])) then return 'invalid' end
  if ARGV[14] == '1' then
    if redis.call('EXISTS', KEYS[13]) ~= 0 then return 'invalid' end
    if decimal_ge(time[1], ARGV[15]) and (time[1] ~= ARGV[15] or tonumber(time[2])*1000 >= tonumber(ARGV[16])) then return 'invalid' end
  end
end
for _, i in ipairs({5,6,7,8,9,10,11}) do
  local expected = 'set'
  if i == 5 then expected = 'string' end
  if i >= 9 then expected = 'zset' end
  if (i ~= 5 and i ~= 8) or ARGV[1] ~= '0' then
    local actual = redis.call('TYPE', KEYS[i]).ok
    if actual ~= 'none' and actual ~= expected then return 'index_type' end
  end
end
if not refresh_grant_acl_allows() or
   not acl_allows('INCR', KEYS[1]) or
   not acl_allows('SET', KEYS[2], ARGV[2]) or
   not acl_allows('SET', KEYS[3], ARGV[3]) or
   not acl_allows('SADD', KEYS[6], ARGV[5]) or
   not acl_allows('SADD', KEYS[7], ARGV[5]) or
   not acl_allows('ZADD', KEYS[9], ARGV[7], ARGV[5]) or
   not acl_allows('ZADD', KEYS[10], ARGV[8], ARGV[5]) then return 'acl_denied' end
if ARGV[1] ~= '0' and not acl_allows('SET', KEYS[5], ARGV[10]) then return 'acl_denied' end
if ARGV[1] == '1' and
   (not acl_allows('SET', KEYS[4], ARGV[4]) or
    not acl_allows('SADD', KEYS[8], ARGV[6]) or
    not acl_allows('ZADD', KEYS[11], ARGV[9], ARGV[6])) then return 'acl_denied' end

-- Index each payload before storing it. Metadata retains the owner of an
-- unpublished access token so expiry/subject cleanup can remove its membership.
redis.call('INCR', KEYS[1])
prepare_refresh_grant_index()
redis.call('ZADD', KEYS[9], ARGV[7], ARGV[5])
redis.call('ZADD', KEYS[10], ARGV[8], ARGV[5])
redis.call('SET', KEYS[3], ARGV[3])
redis.call('SADD', KEYS[7], ARGV[5])
if ARGV[1] == '1' then redis.call('SET', KEYS[2], ARGV[2]) end
redis.call('SADD', KEYS[6], ARGV[5])
if ARGV[1] == '1' then
  redis.call('ZADD', KEYS[11], ARGV[9], ARGV[6])
  redis.call('SET', KEYS[4], ARGV[4])
  redis.call('SADD', KEYS[8], ARGV[6])
end
if ARGV[1] ~= '0' then redis.call('SET', KEYS[5], ARGV[10]) end
-- An initial grant gates both new tokens. An existing grant cannot gate a new
-- descendant, so independent/reminted access is itself published last.
publish_refresh_grant()
if ARGV[1] ~= '1' then redis.call('SET', KEYS[2], ARGV[2]) end
return 'ok'
";

#[derive(Clone, Copy)]
pub(super) struct DirectGrant<'a> {
    pub(super) access: &'a AccessToken,
    pub(super) meta: &'a BearerTokenMeta,
    pub(super) refresh: Option<&'a RefreshToken>,
    pub(super) parent_payload: Option<&'a str>,
    pub(super) children: &'a str,
    pub(super) grant: &'a GrantCommit,
}

impl RedisTokenStoreBackend {
    pub(super) fn commit_direct_grant(
        &self,
        conn: &mut redis::Connection,
        plan: DirectGrant<'_>,
    ) -> Result<String, TokenStoreStorageError> {
        let DirectGrant {
            access,
            meta,
            refresh,
            parent_payload,
            children,
            grant,
        } = plan;
        let mode = if parent_payload.is_some() {
            "2"
        } else if refresh.is_some() {
            "1"
        } else {
            "0"
        };
        let refresh_id = refresh.map_or("", |refresh| refresh.token.as_str());
        let refresh_key = refresh.map_or_else(
            || self.keyspace.version_key(),
            |refresh| self.keyspace.refresh_key(&refresh.token),
        );
        let deadline = optional_deadline(refresh.map(|refresh| refresh.expires_at))?;
        let root = refresh
            .and_then(|token| token.exchange_grant.as_ref())
            .and_then(|grant| grant.root());
        let root_deadline = optional_deadline(root.map(|root| root.expires_at))?;
        let refresh_payload = match refresh {
            Some(token) => encode_redis_json(token)?,
            None => String::new(),
        };
        let script = GrantCommit::script(COMMIT);
        let mut call = script.prepare_invoke();
        call.key(self.keyspace.version_key())
            .key(self.keyspace.access_key(&access.token))
            .key(self.keyspace.bearer_key(&meta.token_id))
            .key(refresh_key)
            .key(self.keyspace.refresh_children_key(refresh_id))
            .key(self.keyspace.subject_access_key(&access.user_id))
            .key(self.keyspace.subject_bearer_key(&meta.user_id))
            .key(refresh.map_or_else(
                || self.keyspace.version_key(),
                |token| self.keyspace.subject_refresh_key(&token.user_id),
            ))
            .key(self.keyspace.expiry_access_key())
            .key(self.keyspace.expiry_bearer_key())
            .key(self.keyspace.expiry_refresh_key())
            .key(self.keyspace.revoked_key(refresh_id))
            .key(
                self.keyspace
                    .revoked_key(root.map_or(refresh_id, |root| root.id.as_str())),
            )
            .arg(mode)
            .arg(encode_redis_json(access)?)
            .arg(encode_redis_json(meta)?)
            .arg(refresh_payload)
            .arg(&access.token)
            .arg(refresh_id)
            .arg(system_time_epoch_secs(access_token_expires_at(access)))
            .arg(system_time_epoch_secs(meta.expires_at))
            .arg(deadline.as_secs())
            .arg(children)
            .arg(parent_payload.unwrap_or(""))
            .arg(deadline.as_secs())
            .arg(deadline.subsec_nanos())
            .arg(if root.is_some() { "1" } else { "0" })
            .arg(root_deadline.as_secs())
            .arg(root_deadline.subsec_nanos());
        grant.append(&mut call);
        call.invoke(conn)
            .map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))
    }
}

// A missing optional record disables the corresponding Lua branch. Zero is only
// its unused positional argument; an invalid present deadline remains an error.
fn optional_deadline(
    deadline: Option<std::time::SystemTime>,
) -> Result<std::time::Duration, TokenStoreStorageError> {
    match deadline {
        Some(deadline) => deadline.duration_since(UNIX_EPOCH).map_err(|_| {
            TokenStoreStorageError::InvariantViolation("grant deadline before epoch".into())
        }),
        None => Ok(std::time::Duration::ZERO),
    }
}
