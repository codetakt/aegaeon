use super::contract::{redis_bool, LuaSlot, RedisScriptArg};

const COMMIT_REFRESH_ROTATION: &str = r#"
if redis.call("EXISTS", KEYS[1]) == 1 then
  return "busy"
end

local now_epoch_secs = tonumber(ARGV[1])
if not now_epoch_secs then
  return "refresh_decode"
end

local function system_time_epoch_secs(value)
  if type(value) == "table" then
    return tonumber(value["secs_since_epoch"])
  end
  return tonumber(value)
end

local revoked_payload = redis.call("GET", KEYS[3])
if revoked_payload then
  local ok, revoked = pcall(cjson.decode, revoked_payload)
  if not ok then
    return "refresh_decode"
  end
  local revoked_expires_at = system_time_epoch_secs(revoked["expires_at"])
  if not revoked_expires_at then
    return "refresh_decode"
  end
  if revoked_expires_at > now_epoch_secs then
    return "invalid"
  end
  redis.call("DEL", KEYS[3])
  redis.call("ZREM", KEYS[4], ARGV[2])
end

local previous_payload = redis.call("GET", KEYS[2])
if not previous_payload then
  return "invalid"
end
if previous_payload ~= ARGV[3] then
  return "stale"
end

local ok, previous = pcall(cjson.decode, previous_payload)
if not ok then
  return "refresh_decode"
end
if previous["rotated"] == true then
  return "reused"
end
local previous_expires_at = system_time_epoch_secs(previous["expires_at"])
if not previous_expires_at then
  return "refresh_decode"
end
if now_epoch_secs >= previous_expires_at then
  redis.call("DEL", KEYS[2])
  redis.call("DEL", KEYS[5])
  redis.call("DEL", KEYS[6])
  redis.call("DEL", KEYS[7])
  redis.call("SREM", KEYS[10], ARGV[2])
  redis.call("ZREM", KEYS[12], ARGV[2])
  redis.call("INCR", KEYS[20])
  return "expired"
end

if redis.call("EXISTS", KEYS[6]) == 1 then
  return "token_collision"
end
if redis.call("EXISTS", KEYS[8]) == 1 then
  return "token_collision"
end
if redis.call("EXISTS", KEYS[9]) == 1 then
  return "token_collision"
end
if redis.call("EXISTS", KEYS[13]) == 1 then
  return "token_collision"
end
if ARGV[11] == "1" and redis.call("EXISTS", KEYS[14]) == 1 then
  return "token_collision"
end
if ARGV[11] == "1" and redis.call("EXISTS", KEYS[17]) == 1 then
  return "token_collision"
end

redis.call("SET", KEYS[2], ARGV[4])
redis.call("SET", KEYS[6], ARGV[8])
redis.call("SET", KEYS[8], ARGV[9])

redis.call("SET", KEYS[9], ARGV[5])
redis.call("SADD", KEYS[11], ARGV[6])
redis.call("ZADD", KEYS[12], ARGV[7], ARGV[6])
redis.call("SET", KEYS[13], ARGV[10])

if ARGV[11] == "1" then
  redis.call("SET", KEYS[14], ARGV[12])
  redis.call("SADD", KEYS[15], ARGV[13])
  redis.call("ZADD", KEYS[16], ARGV[14], ARGV[13])
  redis.call("SET", KEYS[17], ARGV[15])
  redis.call("SADD", KEYS[18], ARGV[16])
  redis.call("ZADD", KEYS[19], ARGV[17], ARGV[16])
end

redis.call("INCR", KEYS[20])
return "ok"
"#;
const REFRESH_ROTATION_COMMIT_KEY_PLAN: [LuaSlot; 20] = [
    LuaSlot::new(1, "mutation_barrier"),
    LuaSlot::new(2, "previous_refresh"),
    LuaSlot::new(3, "previous_revoked"),
    LuaSlot::new(4, "revoked_expiry"),
    LuaSlot::new(5, "previous_children"),
    LuaSlot::new(6, "previous_successor"),
    LuaSlot::new(7, "previous_predecessor"),
    LuaSlot::new(8, "new_predecessor"),
    LuaSlot::new(9, "new_refresh"),
    LuaSlot::new(10, "previous_subject_refresh"),
    LuaSlot::new(11, "subject_refresh"),
    LuaSlot::new(12, "refresh_expiry"),
    LuaSlot::new(13, "new_children"),
    LuaSlot::new(14, "access"),
    LuaSlot::new(15, "subject_access"),
    LuaSlot::new(16, "access_expiry"),
    LuaSlot::new(17, "bearer"),
    LuaSlot::new(18, "subject_bearer"),
    LuaSlot::new(19, "bearer_expiry"),
    LuaSlot::new(20, "version"),
];
const REFRESH_ROTATION_COMMIT_ARG_PLAN: [LuaSlot; 17] = [
    LuaSlot::new(1, "now_epoch_secs"),
    LuaSlot::new(2, "previous_refresh_token"),
    LuaSlot::new(3, "expected_previous_payload"),
    LuaSlot::new(4, "rotated_previous_payload"),
    LuaSlot::new(5, "new_refresh_payload"),
    LuaSlot::new(6, "new_refresh_token"),
    LuaSlot::new(7, "new_refresh_expires_at_epoch_secs"),
    LuaSlot::new(8, "successor_payload"),
    LuaSlot::new(9, "predecessor_payload"),
    LuaSlot::new(10, "new_children_payload"),
    LuaSlot::new(11, "has_grant"),
    LuaSlot::new(12, "access_payload"),
    LuaSlot::new(13, "access_token"),
    LuaSlot::new(14, "access_expires_at_epoch_secs"),
    LuaSlot::new(15, "bearer_payload"),
    LuaSlot::new(16, "bearer_token_id"),
    LuaSlot::new(17, "bearer_expires_at_epoch_secs"),
];
const REFRESH_ROTATION_COMMIT_KEY_COUNT: usize = REFRESH_ROTATION_COMMIT_KEY_PLAN.len();
const REFRESH_ROTATION_COMMIT_ARG_COUNT: usize = REFRESH_ROTATION_COMMIT_ARG_PLAN.len();

#[derive(Clone, Copy)]
pub(in crate::authcode::store::redis_backend) struct RefreshRotationCommitKeys<'a> {
    pub(in crate::authcode::store::redis_backend) mutation_barrier: &'a str,
    pub(in crate::authcode::store::redis_backend) previous_refresh: &'a str,
    pub(in crate::authcode::store::redis_backend) previous_revoked: &'a str,
    pub(in crate::authcode::store::redis_backend) revoked_expiry: &'a str,
    pub(in crate::authcode::store::redis_backend) previous_children: &'a str,
    pub(in crate::authcode::store::redis_backend) previous_successor: &'a str,
    pub(in crate::authcode::store::redis_backend) previous_predecessor: &'a str,
    pub(in crate::authcode::store::redis_backend) new_predecessor: &'a str,
    pub(in crate::authcode::store::redis_backend) new_refresh: &'a str,
    pub(in crate::authcode::store::redis_backend) previous_subject_refresh: &'a str,
    pub(in crate::authcode::store::redis_backend) subject_refresh: &'a str,
    pub(in crate::authcode::store::redis_backend) refresh_expiry: &'a str,
    pub(in crate::authcode::store::redis_backend) new_children: &'a str,
    pub(in crate::authcode::store::redis_backend) access: &'a str,
    pub(in crate::authcode::store::redis_backend) subject_access: &'a str,
    pub(in crate::authcode::store::redis_backend) access_expiry: &'a str,
    pub(in crate::authcode::store::redis_backend) bearer: &'a str,
    pub(in crate::authcode::store::redis_backend) subject_bearer: &'a str,
    pub(in crate::authcode::store::redis_backend) bearer_expiry: &'a str,
    pub(in crate::authcode::store::redis_backend) version: &'a str,
}

#[derive(Clone, Copy)]
pub(in crate::authcode::store::redis_backend) struct RefreshRotationCommitArgs<'a> {
    pub(in crate::authcode::store::redis_backend) now_epoch_secs: u64,
    pub(in crate::authcode::store::redis_backend) previous_refresh_token: &'a str,
    pub(in crate::authcode::store::redis_backend) expected_previous_payload: &'a str,
    pub(in crate::authcode::store::redis_backend) rotated_previous_payload: &'a str,
    pub(in crate::authcode::store::redis_backend) new_refresh_payload: &'a str,
    pub(in crate::authcode::store::redis_backend) new_refresh_token: &'a str,
    pub(in crate::authcode::store::redis_backend) new_refresh_expires_at_epoch_secs: u64,
    pub(in crate::authcode::store::redis_backend) successor_payload: &'a str,
    pub(in crate::authcode::store::redis_backend) predecessor_payload: &'a str,
    pub(in crate::authcode::store::redis_backend) new_children_payload: &'a str,
    pub(in crate::authcode::store::redis_backend) has_grant: bool,
    pub(in crate::authcode::store::redis_backend) access_payload: &'a str,
    pub(in crate::authcode::store::redis_backend) access_token: &'a str,
    pub(in crate::authcode::store::redis_backend) access_expires_at_epoch_secs: u64,
    pub(in crate::authcode::store::redis_backend) bearer_payload: &'a str,
    pub(in crate::authcode::store::redis_backend) bearer_token_id: &'a str,
    pub(in crate::authcode::store::redis_backend) bearer_expires_at_epoch_secs: u64,
}

impl<'a> RefreshRotationCommitKeys<'a> {
    fn ordered(&self) -> [&'a str; REFRESH_ROTATION_COMMIT_KEY_COUNT] {
        [
            self.mutation_barrier,
            self.previous_refresh,
            self.previous_revoked,
            self.revoked_expiry,
            self.previous_children,
            self.previous_successor,
            self.previous_predecessor,
            self.new_predecessor,
            self.new_refresh,
            self.previous_subject_refresh,
            self.subject_refresh,
            self.refresh_expiry,
            self.new_children,
            self.access,
            self.subject_access,
            self.access_expiry,
            self.bearer,
            self.subject_bearer,
            self.bearer_expiry,
            self.version,
        ]
    }
}

impl<'a> RefreshRotationCommitArgs<'a> {
    fn ordered(&self) -> [RedisScriptArg<'a>; REFRESH_ROTATION_COMMIT_ARG_COUNT] {
        [
            RedisScriptArg::U64(self.now_epoch_secs),
            RedisScriptArg::Str(self.previous_refresh_token),
            RedisScriptArg::Str(self.expected_previous_payload),
            RedisScriptArg::Str(self.rotated_previous_payload),
            RedisScriptArg::Str(self.new_refresh_payload),
            RedisScriptArg::Str(self.new_refresh_token),
            RedisScriptArg::U64(self.new_refresh_expires_at_epoch_secs),
            RedisScriptArg::Str(self.successor_payload),
            RedisScriptArg::Str(self.predecessor_payload),
            RedisScriptArg::Str(self.new_children_payload),
            RedisScriptArg::Bool(self.has_grant),
            RedisScriptArg::Str(self.access_payload),
            RedisScriptArg::Str(self.access_token),
            RedisScriptArg::U64(self.access_expires_at_epoch_secs),
            RedisScriptArg::Str(self.bearer_payload),
            RedisScriptArg::Str(self.bearer_token_id),
            RedisScriptArg::U64(self.bearer_expires_at_epoch_secs),
        ]
    }
}

pub(in crate::authcode::store::redis_backend) fn invoke_refresh_rotation_commit(
    conn: &mut redis::Connection,
    keys: RefreshRotationCommitKeys<'_>,
    args: RefreshRotationCommitArgs<'_>,
) -> redis::RedisResult<String> {
    let script = redis::Script::new(COMMIT_REFRESH_ROTATION);
    let mut invocation = script.prepare_invoke();
    for key in keys.ordered() {
        invocation.key(key);
    }
    for arg in args.ordered() {
        match arg {
            RedisScriptArg::Str(value) => {
                invocation.arg(value);
            }
            RedisScriptArg::U64(value) => {
                invocation.arg(value);
            }
            RedisScriptArg::Bool(value) => {
                invocation.arg(redis_bool(value));
            }
        }
    }
    invocation.invoke::<String>(conn)
}

#[cfg(test)]
mod tests;
