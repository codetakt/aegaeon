use super::RedisTokenStoreBackend;
use crate::authcode::store::redis_support::encode_redis_json;
use crate::authcode::store::TokenStoreStorageError;
use crate::authcode::types::{RefreshGrantRecord, RefreshGrantRef};
use std::time::{SystemTime, UNIX_EPOCH};

/// Appended envelope: three keys and eight arguments. Existing script slots stay
/// fixed. Publishers can separate expiry preparation from final authority
/// publication; the combined helper preserves adjacent callers' commit shape.
pub(super) struct GrantCommit {
    keys: [String; 3],
    args: [String; 8],
}

const PREPARE: &str = r"
local gk = #KEYS - 2
local ga = #ARGV - 7
local grant_mode = ARGV[ga]
local version_type = redis.call('TYPE', KEYS[gk+2]).ok
if version_type ~= 'none' and version_type ~= 'string' then return 'version_type' end
local version = redis.call('GET', KEYS[gk+2]) or '0'
if not string.match(version, '^%d+$') or #version > 19 or (#version == 19 and version > '9223372036854775806') then return 'version_exhausted' end
local function decimal_ge(a, b)
  if #a ~= #b then return #a > #b end
  return a >= b
end
if grant_mode ~= '0' then
  local kind = redis.call('TYPE', KEYS[gk]).ok
  local index_kind = redis.call('TYPE', KEYS[gk+1]).ok
  if (kind ~= 'none' and kind ~= 'string') or (index_kind ~= 'none' and index_kind ~= 'zset') then return 'grant_type' end
  if grant_mode == '1' then
    if redis.call('EXISTS', KEYS[gk]) ~= 0 then return 'token_collision' end
  elseif grant_mode == '2' then
    if redis.call('GET', KEYS[gk]) ~= ARGV[ga+1] then return 'invalid' end
  else return 'invalid' end
  local time = redis.call('TIME')
  if decimal_ge(time[1], ARGV[ga+6]) then
    if time[1] ~= ARGV[ga+6] or tonumber(time[2]) * 1000 >= tonumber(ARGV[ga+7]) then return 'invalid' end
  end
end
-- Older engines lack this helper. Publication ordering remains the safety
-- boundary there; a present malformed capability must never permit a write.
local acl_check = rawget(redis, 'acl_check_cmd')
local function acl_allows(...)
  if acl_check == nil then return true end
  return type(acl_check) == 'function' and acl_check(...) == true
end
local function refresh_grant_acl_allows()
  return grant_mode == '0' or
    (acl_allows('ZADD', KEYS[gk+1], ARGV[ga+4], ARGV[ga+3]) and
     acl_allows('SET', KEYS[gk], ARGV[ga+2]))
end
local function prepare_refresh_grant_index()
  if grant_mode ~= '0' then
    redis.call('ZADD', KEYS[gk+1], ARGV[ga+4], ARGV[ga+3])
  end
end
local function publish_refresh_grant()
  if grant_mode ~= '0' then redis.call('SET', KEYS[gk], ARGV[ga+2]) end
end
local function commit_refresh_grant()
  prepare_refresh_grant_index()
  publish_refresh_grant()
end
";

impl GrantCommit {
    #[cfg(test)]
    pub(in crate::authcode::store::redis_backend) fn independent_for_test(version: &str) -> Self {
        Self {
            keys: [version.into(), version.into(), version.into()],
            args: [
                "0".into(),
                String::new(),
                String::new(),
                String::new(),
                "0".into(),
                String::new(),
                "0".into(),
                "0".into(),
            ],
        }
    }

    pub(super) fn script(body: &str) -> redis::Script {
        redis::Script::new(&format!("{PREPARE}\n{body}"))
    }

    pub(super) fn append(&self, invocation: &mut redis::ScriptInvocation<'_>) {
        #[cfg(test)]
        barriers::pause(&self.keys[0], "commit");
        invocation.key(&self.keys).arg(&self.args);
    }

    pub(super) fn initial(
        backend: &RedisTokenStoreBackend,
        record: Option<&RefreshGrantRecord>,
    ) -> Result<Self, TokenStoreStorageError> {
        match record {
            Some(record) => Self::plan(backend, "1", "", record, record.retain_until),
            None => Ok(Self {
                keys: [
                    backend.keyspace.version_key(),
                    backend.keyspace.version_key(),
                    backend.keyspace.version_key(),
                ],
                args: [
                    "0".into(),
                    String::new(),
                    String::new(),
                    String::new(),
                    "0".into(),
                    String::new(),
                    "0".into(),
                    "0".into(),
                ],
            }),
        }
    }

    fn plan(
        backend: &RedisTokenStoreBackend,
        mode: &str,
        expected: &str,
        record: &RefreshGrantRecord,
        active_deadline: SystemTime,
    ) -> Result<Self, TokenStoreStorageError> {
        let deadline = active_deadline.duration_since(UNIX_EPOCH).map_err(|_| {
            TokenStoreStorageError::InvariantViolation("refresh grant deadline before epoch".into())
        })?;
        let duration = record
            .retain_until
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                TokenStoreStorageError::InvariantViolation(
                    "refresh grant retention before epoch".into(),
                )
            })?;
        let seconds = duration
            .as_secs()
            .checked_add(u64::from(duration.subsec_nanos() > 0))
            .ok_or_else(|| {
                TokenStoreStorageError::InvariantViolation(
                    "refresh grant retention overflow".into(),
                )
            })?;
        // Redis zset scores are doubles. Round upward if the integer cast rounded
        // down, then still compare the exact record in cleanup before deletion.
        let mut score = seconds as f64;
        if (score as u128) < u128::from(seconds) {
            score = score.next_up();
        }
        Ok(Self {
            keys: [
                backend.keyspace.refresh_grant_key(&record.reference.id),
                backend.keyspace.expiry_refresh_grant_key(),
                backend.keyspace.version_key(),
            ],
            args: [
                mode.into(),
                expected.into(),
                encode_redis_json(record)?,
                record.reference.id.clone(),
                score.to_string(),
                String::new(),
                deadline.as_secs().to_string(),
                deadline.subsec_nanos().to_string(),
            ],
        })
    }
}

impl RedisTokenStoreBackend {
    /// The denial commits before any bounded physical family cleanup. An error
    /// from later cleanup or a lost reply does not imply that denial rolled back.
    pub(super) fn revoke_refresh_grant(
        &self,
        conn: &mut redis::Connection,
        reference: Option<&RefreshGrantRef>,
        client: &str,
        user: &str,
    ) -> Result<(), TokenStoreStorageError> {
        let Some(reference) = reference else {
            return Ok(());
        };
        for _ in 0..super::super::redis_support::TOKEN_STORE_REDIS_LOCK_RETRIES {
            let Some((raw, mut record)) = self.refresh_grant_raw(conn, reference)? else {
                return Ok(());
            };
            if !record.matches(reference, client, user) {
                return Err(TokenStoreStorageError::InvariantViolation(
                    "refresh grant binding mismatch".into(),
                ));
            }
            if record.revoked {
                return Ok(());
            }
            record.revoked = true;
            let outcome: i64 = redis::Script::new("if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end; redis.call('SET', KEYS[1], ARGV[2]); return 1")
                .key(self.keyspace.refresh_grant_key(&reference.id)).arg(raw).arg(encode_redis_json(&record)?)
                .invoke(conn).map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))?;
            if outcome == 1 {
                return Ok(());
            }
        }
        Err(TokenStoreStorageError::BackendUnavailable(
            "refresh grant revocation contention".into(),
        ))
    }

    pub(super) fn cleanup_refresh_grants(
        &self,
        conn: &mut redis::Connection,
        now: SystemTime,
    ) -> Result<(), TokenStoreStorageError> {
        // Persist a bounded rank cursor so malformed retained records at the
        // front cannot starve later decisions. Each call examines at most 256.
        let ids: Vec<String> = redis::Script::new(
            r"
local count = redis.call('ZCARD', KEYS[1])
if count == 0 then redis.call('DEL', KEYS[2]); return {} end
local offset = tonumber(redis.call('GET', KEYS[2]) or '0')
if not offset or offset < 0 or offset ~= math.floor(offset) then offset = 0 end
offset = offset % count
local result = redis.call('ZRANGE', KEYS[1], offset, offset + 255)
redis.call('SET', KEYS[2], (offset + 256) % count)
return result
",
        )
        .key(self.keyspace.expiry_refresh_grant_key())
        .key(self.keyspace.refresh_grant_cleanup_cursor_key())
        .invoke(conn)
        .map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))?;
        for id in ids {
            let reference = RefreshGrantRef { version: 1, id };
            let Some((raw, record)) = self.refresh_grant_raw(conn, &reference)? else {
                // Only remove orphan index entries if the key is still absent.
                // Malformed records retain their bytes and unknown retention.
                let _: i64 = redis::Script::new("if redis.call('EXISTS', KEYS[1]) == 0 then return redis.call('ZREM', KEYS[2], ARGV[1]) end; return 0")
                    .key(self.keyspace.refresh_grant_key(&reference.id))
                    .key(self.keyspace.expiry_refresh_grant_key()).arg(&reference.id)
                    .invoke(conn).map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))?;
                continue;
            };
            if record.reference != reference || record.version != 1 || now < record.retain_until {
                continue;
            }
            #[cfg(test)]
            barriers::pause(&self.keyspace.refresh_grant_key(&reference.id), "cleanup");
            // An extension or revocation changes the complete expected record.
            let _: i64 = redis::Script::new("if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end; redis.call('DEL', KEYS[1]); redis.call('ZREM', KEYS[2], ARGV[2]); return 1")
                .key(self.keyspace.refresh_grant_key(&reference.id)).key(self.keyspace.expiry_refresh_grant_key()).arg(raw).arg(&reference.id)
                .invoke(conn).map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))?;
        }
        Ok(())
    }

    pub(super) fn refresh_grant_raw(
        &self,
        conn: &mut redis::Connection,
        reference: &RefreshGrantRef,
    ) -> Result<Option<(String, RefreshGrantRecord)>, TokenStoreStorageError> {
        if !reference.supported() {
            return Ok(None);
        }
        let raw: Option<String> = redis::cmd("GET")
            .arg(self.keyspace.refresh_grant_key(&reference.id))
            .query(conn)
            .map_err(|error| TokenStoreStorageError::BackendUnavailable(error.to_string()))?;
        Ok(raw.and_then(|raw| {
            serde_json::from_str::<RefreshGrantRecord>(&raw)
                .ok()
                .map(|record| (raw, record))
        }))
    }

    pub(in crate::authcode::store) fn observed_grant_active(
        &self,
        reference: &RefreshGrantRef,
        client: &str,
        user: &str,
        deadline: SystemTime,
    ) -> Result<bool, TokenStoreStorageError> {
        self.refresh_grant_active(
            &mut self.connection()?,
            Some(reference),
            client,
            user,
            deadline,
            SystemTime::now(),
        )
    }

    pub(super) fn refresh_grant_active(
        &self,
        conn: &mut redis::Connection,
        reference: Option<&RefreshGrantRef>,
        client: &str,
        user: &str,
        deadline: SystemTime,
        now: SystemTime,
    ) -> Result<bool, TokenStoreStorageError> {
        let Some(reference) = reference else {
            return Ok(false);
        };
        Ok(self
            .refresh_grant_raw(conn, reference)?
            .is_some_and(|(_, record)| {
                record.active(reference, client, user, now) && record.retain_until >= deadline
            }))
    }

    pub(super) fn descendant_grant_commit(
        &self,
        conn: &mut redis::Connection,
        reference: Option<&RefreshGrantRef>,
        client: &str,
        user: &str,
        deadline: SystemTime,
    ) -> Result<Option<GrantCommit>, TokenStoreStorageError> {
        let Some(reference) = reference else {
            return Ok(None);
        };
        let Some((raw, mut record)) = self.refresh_grant_raw(conn, reference)? else {
            return Ok(None);
        };
        if !record.active(reference, client, user, SystemTime::now()) {
            return Ok(None);
        }
        let previous_deadline = record.retain_until;
        record.retain_until = record.retain_until.max(deadline);
        GrantCommit::plan(self, "2", &raw, &record, previous_deadline).map(Some)
    }
}
#[cfg(test)]
impl RedisTokenStoreBackend {
    pub(crate) fn install_grant_pause_for_tests(
        &self,
        reference: &RefreshGrantRef,
        phase: &'static str,
    ) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let key = if phase == "snapshot" {
            self.keyspace.version_key()
        } else {
            self.keyspace.refresh_grant_key(&reference.id)
        };
        barriers::install(key, phase)
    }
    pub(crate) fn cleanup_grants_at_for_tests(
        &self,
        now: SystemTime,
    ) -> Result<(), TokenStoreStorageError> {
        self.cleanup_refresh_grants(&mut self.connection()?, now)
    }
    pub(super) fn snapshot_pause_for_tests(&self) {
        barriers::pause(&self.keyspace.version_key(), "snapshot");
    }
}

#[cfg(test)]
mod barriers {
    use std::collections::HashMap;
    use std::sync::{mpsc, LazyLock, Mutex};
    type Pause = (mpsc::Sender<()>, mpsc::Receiver<()>);
    static PAUSES: LazyLock<Mutex<HashMap<(String, &'static str), Pause>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    pub(super) fn install(
        key: String,
        phase: &'static str,
    ) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (reached, observed) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        assert!(PAUSES
            .lock()
            .unwrap()
            .insert((key, phase), (reached, resume))
            .is_none());
        (observed, release)
    }
    pub(super) fn pause(key: &str, phase: &'static str) {
        let pause = PAUSES.lock().unwrap().remove(&(key.into(), phase));
        if let Some((reached, resume)) = pause {
            reached.send(()).expect("barrier receiver");
            resume
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("barrier released");
        }
    }
}

#[cfg(test)]
mod acl_tests {
    #[test]
    #[ignore = "requires AEGAEON_TEST_REDIS_URL; synthetic Lua capability values"]
    fn redis_grant_acl_capability_absent_or_malformed() {
        let mut conn = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL").unwrap())
            .unwrap()
            .get_connection()
            .unwrap();
        for (capability, expected) in [("nil", "ok"), ("true", "acl_denied")] {
            let key = format!("grant-acl-synthetic:{}", uuid::Uuid::new_v4());
            let source = format!(
                "local redis = {{call=redis.call, acl_check_cmd={capability}}}\n{}\n\
                 if not acl_allows('SET', KEYS[1], 'published') then return 'acl_denied' end\n\
                 redis.call('SET', KEYS[1], 'published'); return 'ok'",
                super::PREPARE,
            );
            let result: String = redis::Script::new(&source)
                .key(&[&key, &key, &key])
                .arg(&["0", "", "", "", "0", "", "0", "0"])
                .invoke(&mut conn)
                .unwrap();
            assert_eq!(result, expected);
            let stored: Option<String> = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
            assert_eq!(stored.as_deref(), (expected == "ok").then_some("published"));
            redis::cmd("DEL").arg(&key).query::<()>(&mut conn).unwrap();
        }
    }
}
