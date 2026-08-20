mod contract;
mod refresh_rotation;

pub(super) use refresh_rotation::{
    invoke_refresh_rotation_commit, RefreshRotationCommitArgs, RefreshRotationCommitKeys,
};

use contract::{redis_bool, LuaSlot, RedisScriptArg};

const RELEASE_LOCK_IF_OWNER: &str = r"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
";

const COMMIT_AUTHORIZATION_CODE_GRANT: &str = r#"
local code_payload = redis.call("GET", KEYS[1])
if not code_payload then
  return "missing_code"
end
if code_payload ~= ARGV[21] then
  return "code_mismatch"
end

if redis.call("EXISTS", KEYS[4]) == 1 then
  return "token_collision"
end
if ARGV[6] == "1" and redis.call("EXISTS", KEYS[7]) == 1 then
  return "token_collision"
end
if ARGV[6] == "1" and redis.call("EXISTS", KEYS[10]) == 1 then
  return "token_collision"
end
if redis.call("EXISTS", KEYS[11]) == 1 then
  return "token_collision"
end

local refresh_children_payload = nil
if ARGV[6] == "1" then
  local seen = {}
  local current = redis.call("GET", KEYS[10])
  if current then
    local ok, decoded = pcall(cjson.decode, current)
    if not ok then
      return "refresh_children_decode"
    end
    local tokens = decoded["access_tokens"] or {}
    for _, token in ipairs(tokens) do
      seen[token] = true
    end
  end
  seen[ARGV[4]] = true

  local tokens = {}
  for token, _ in pairs(seen) do
    table.insert(tokens, token)
  end
  table.sort(tokens)
  refresh_children_payload = cjson.encode({
    refresh_token = ARGV[7],
    access_tokens = tokens
  })
end

local oidc_enabled = ARGV[11] == "1"
local oidc_create_session = false
if oidc_enabled then
  local oidc_user_id = ARGV[12]
  local oidc_auth_session_key = ARGV[13]
  local oidc_user_sessions_key = ARGV[14]
  local oidc_sid = ARGV[15]
  local oidc_now_epoch_secs = tonumber(ARGV[16])
  local oidc_ttl_secs = tonumber(ARGV[17])
  local oidc_session_key_prefix = ARGV[18]
  local oidc_clients_key_prefix = ARGV[19]
  local oidc_client_id = ARGV[20]
  if oidc_user_id == "" or oidc_auth_session_key == "" or oidc_user_sessions_key == ""
    or oidc_sid == "" or oidc_client_id == "" or not oidc_now_epoch_secs
    or not oidc_ttl_secs or oidc_ttl_secs < 1 or oidc_session_key_prefix == ""
    or oidc_clients_key_prefix == "" then
    return "oidc_session_invalid"
  end

  local function cleanup_oidc_sid(sid)
    local session_key = oidc_session_key_prefix .. sid
    local clients_key = oidc_clients_key_prefix .. sid
    local stored_auth_session_key = redis.call("HGET", session_key, "auth_session_key")
    local stored_user_sessions_key = redis.call("HGET", session_key, "user_sessions_key")
    if stored_auth_session_key and redis.call("GET", stored_auth_session_key) == sid then
      redis.call("DEL", stored_auth_session_key)
    end
    if stored_user_sessions_key then
      redis.call("SREM", stored_user_sessions_key, sid)
      if redis.call("SCARD", stored_user_sessions_key) == 0 then
        redis.call("DEL", stored_user_sessions_key)
      end
    end
    redis.call("DEL", session_key)
    redis.call("DEL", clients_key)
    redis.call("ZREM", KEYS[16], sid)
  end

  local function oidc_logged_out_expired(logged_out_at_text)
    local logged_out_at = tonumber(logged_out_at_text)
    if not logged_out_at then
      return true
    end
    return logged_out_at > oidc_now_epoch_secs or oidc_now_epoch_secs - logged_out_at >= oidc_ttl_secs
  end

  local current_sid = redis.call("GET", KEYS[14])
  if current_sid then
    local current_session_key = oidc_session_key_prefix .. current_sid
    local values = redis.call(
      "HMGET", current_session_key,
      "user_id", "auth_session_key", "user_sessions_key", "logout_jti", "logged_out_at_epoch_secs"
    )
    if values[1] and values[2] and values[3] and values[4] and values[5]
      and values[2] == oidc_auth_session_key and values[3] == oidc_user_sessions_key
      and values[1] == oidc_user_id then
      if values[4] == "" and values[5] == "" then
        if current_sid ~= oidc_sid then
          return "oidc_session_conflict"
        end
      elseif values[4] ~= "" and values[5] ~= "" and not oidc_logged_out_expired(values[5]) then
        redis.call("DEL", KEYS[14])
        oidc_create_session = true
      else
        cleanup_oidc_sid(current_sid)
        oidc_create_session = true
      end
    elseif not values[1] or not values[2] or not values[3] or not values[4] or not values[5] then
      cleanup_oidc_sid(current_sid)
      oidc_create_session = true
    else
      if values[2] == oidc_auth_session_key then
        cleanup_oidc_sid(current_sid)
      else
        redis.call("DEL", KEYS[14])
      end
      oidc_create_session = true
    end
  else
    oidc_create_session = true
  end

  if oidc_create_session and redis.call("EXISTS", KEYS[15]) == 1 then
    return "oidc_session_collision"
  end
end

redis.call("SET", KEYS[4], ARGV[1])
redis.call("SADD", KEYS[5], ARGV[4])
redis.call("ZADD", KEYS[6], ARGV[5], ARGV[4])

if ARGV[6] == "1" then
  redis.call("SET", KEYS[7], ARGV[2])
  redis.call("SADD", KEYS[8], ARGV[7])
  redis.call("ZADD", KEYS[9], ARGV[8], ARGV[7])
  redis.call("SET", KEYS[10], refresh_children_payload)
end

redis.call("SET", KEYS[11], ARGV[3])
redis.call("SADD", KEYS[12], ARGV[9])
redis.call("ZADD", KEYS[13], ARGV[10], ARGV[9])

if oidc_enabled then
  if oidc_create_session then
    redis.call(
      "HSET", KEYS[15],
      "user_id", ARGV[12],
      "auth_session_key", ARGV[13],
      "user_sessions_key", ARGV[14],
      "logout_jti", "",
      "logged_out_at_epoch_secs", ""
    )
    redis.call("SET", KEYS[14], ARGV[15])
    redis.call("SADD", KEYS[17], ARGV[15])
  end
  redis.call("SADD", KEYS[18], ARGV[20])
end

redis.call("DEL", KEYS[1])
redis.call("INCR", KEYS[2])
redis.call("INCR", KEYS[3])
return "ok"
"#;
const AUTHORIZATION_CODE_GRANT_COMMIT_KEY_PLAN: [LuaSlot; 18] = [
    LuaSlot::new(1, "auth_code"),
    LuaSlot::new(2, "auth_code_version"),
    LuaSlot::new(3, "token_version"),
    LuaSlot::new(4, "access"),
    LuaSlot::new(5, "subject_access"),
    LuaSlot::new(6, "access_expiry"),
    LuaSlot::new(7, "refresh"),
    LuaSlot::new(8, "subject_refresh"),
    LuaSlot::new(9, "refresh_expiry"),
    LuaSlot::new(10, "refresh_children"),
    LuaSlot::new(11, "bearer"),
    LuaSlot::new(12, "subject_bearer"),
    LuaSlot::new(13, "bearer_expiry"),
    LuaSlot::new(14, "oidc_auth_session"),
    LuaSlot::new(15, "oidc_session"),
    LuaSlot::new(16, "oidc_logged_out_expiries"),
    LuaSlot::new(17, "oidc_user_sessions"),
    LuaSlot::new(18, "oidc_clients"),
];
const AUTHORIZATION_CODE_GRANT_COMMIT_ARG_PLAN: [LuaSlot; 21] = [
    LuaSlot::new(1, "access_payload"),
    LuaSlot::new(2, "refresh_payload"),
    LuaSlot::new(3, "bearer_payload"),
    LuaSlot::new(4, "access_token"),
    LuaSlot::new(5, "access_expires_at_epoch_secs"),
    LuaSlot::new(6, "has_refresh"),
    LuaSlot::new(7, "refresh_token"),
    LuaSlot::new(8, "refresh_expires_at_epoch_secs"),
    LuaSlot::new(9, "bearer_token_id"),
    LuaSlot::new(10, "bearer_expires_at_epoch_secs"),
    LuaSlot::new(11, "has_oidc_session"),
    LuaSlot::new(12, "oidc_user_id"),
    LuaSlot::new(13, "oidc_auth_session_key"),
    LuaSlot::new(14, "oidc_user_sessions_key"),
    LuaSlot::new(15, "oidc_sid"),
    LuaSlot::new(16, "oidc_now_epoch_secs"),
    LuaSlot::new(17, "oidc_ttl_secs"),
    LuaSlot::new(18, "oidc_session_key_prefix"),
    LuaSlot::new(19, "oidc_clients_key_prefix"),
    LuaSlot::new(20, "oidc_client_id"),
    LuaSlot::new(21, "expected_code_payload"),
];
const AUTHORIZATION_CODE_GRANT_COMMIT_KEY_COUNT: usize =
    AUTHORIZATION_CODE_GRANT_COMMIT_KEY_PLAN.len();
const AUTHORIZATION_CODE_GRANT_COMMIT_ARG_COUNT: usize =
    AUTHORIZATION_CODE_GRANT_COMMIT_ARG_PLAN.len();

#[derive(Clone, Copy)]
pub(super) struct AuthorizationCodeGrantCommitKeys<'a> {
    pub(super) auth_code: &'a str,
    pub(super) auth_code_version: &'a str,
    pub(super) token_version: &'a str,
    pub(super) access: &'a str,
    pub(super) subject_access: &'a str,
    pub(super) access_expiry: &'a str,
    pub(super) refresh: &'a str,
    pub(super) subject_refresh: &'a str,
    pub(super) refresh_expiry: &'a str,
    pub(super) refresh_children: &'a str,
    pub(super) bearer: &'a str,
    pub(super) subject_bearer: &'a str,
    pub(super) bearer_expiry: &'a str,
    pub(super) oidc_auth_session: &'a str,
    pub(super) oidc_session: &'a str,
    pub(super) oidc_logged_out_expiries: &'a str,
    pub(super) oidc_user_sessions: &'a str,
    pub(super) oidc_clients: &'a str,
}

#[derive(Clone, Copy)]
pub(super) struct AuthorizationCodeGrantCommitArgs<'a> {
    pub(super) access_payload: &'a str,
    pub(super) refresh_payload: &'a str,
    pub(super) bearer_payload: &'a str,
    pub(super) access_token: &'a str,
    pub(super) access_expires_at_epoch_secs: u64,
    pub(super) has_refresh: bool,
    pub(super) refresh_token: &'a str,
    pub(super) refresh_expires_at_epoch_secs: u64,
    pub(super) bearer_token_id: &'a str,
    pub(super) bearer_expires_at_epoch_secs: u64,
    pub(super) has_oidc_session: bool,
    pub(super) oidc_user_id: &'a str,
    pub(super) oidc_auth_session_key: &'a str,
    pub(super) oidc_user_sessions_key: &'a str,
    pub(super) oidc_sid: &'a str,
    pub(super) oidc_now_epoch_secs: u64,
    pub(super) oidc_ttl_secs: u64,
    pub(super) oidc_session_key_prefix: &'a str,
    pub(super) oidc_clients_key_prefix: &'a str,
    pub(super) oidc_client_id: &'a str,
    pub(super) expected_code_payload: &'a str,
}

impl<'a> AuthorizationCodeGrantCommitKeys<'a> {
    fn ordered(&self) -> [&'a str; AUTHORIZATION_CODE_GRANT_COMMIT_KEY_COUNT] {
        [
            self.auth_code,
            self.auth_code_version,
            self.token_version,
            self.access,
            self.subject_access,
            self.access_expiry,
            self.refresh,
            self.subject_refresh,
            self.refresh_expiry,
            self.refresh_children,
            self.bearer,
            self.subject_bearer,
            self.bearer_expiry,
            self.oidc_auth_session,
            self.oidc_session,
            self.oidc_logged_out_expiries,
            self.oidc_user_sessions,
            self.oidc_clients,
        ]
    }
}

impl<'a> AuthorizationCodeGrantCommitArgs<'a> {
    fn ordered(&self) -> [RedisScriptArg<'a>; AUTHORIZATION_CODE_GRANT_COMMIT_ARG_COUNT] {
        [
            RedisScriptArg::Str(self.access_payload),
            RedisScriptArg::Str(self.refresh_payload),
            RedisScriptArg::Str(self.bearer_payload),
            RedisScriptArg::Str(self.access_token),
            RedisScriptArg::U64(self.access_expires_at_epoch_secs),
            RedisScriptArg::Bool(self.has_refresh),
            RedisScriptArg::Str(self.refresh_token),
            RedisScriptArg::U64(self.refresh_expires_at_epoch_secs),
            RedisScriptArg::Str(self.bearer_token_id),
            RedisScriptArg::U64(self.bearer_expires_at_epoch_secs),
            RedisScriptArg::Bool(self.has_oidc_session),
            RedisScriptArg::Str(self.oidc_user_id),
            RedisScriptArg::Str(self.oidc_auth_session_key),
            RedisScriptArg::Str(self.oidc_user_sessions_key),
            RedisScriptArg::Str(self.oidc_sid),
            RedisScriptArg::U64(self.oidc_now_epoch_secs),
            RedisScriptArg::U64(self.oidc_ttl_secs),
            RedisScriptArg::Str(self.oidc_session_key_prefix),
            RedisScriptArg::Str(self.oidc_clients_key_prefix),
            RedisScriptArg::Str(self.oidc_client_id),
            RedisScriptArg::Str(self.expected_code_payload),
        ]
    }
}

pub(super) fn invoke_authorization_code_grant_commit(
    conn: &mut redis::Connection,
    keys: AuthorizationCodeGrantCommitKeys<'_>,
    args: AuthorizationCodeGrantCommitArgs<'_>,
) -> redis::RedisResult<String> {
    let script = commit_authorization_code_grant_script();
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

pub(super) fn release_lock_if_owner_script() -> redis::Script {
    redis::Script::new(RELEASE_LOCK_IF_OWNER)
}

pub(super) fn commit_authorization_code_grant_script() -> redis::Script {
    redis::Script::new(COMMIT_AUTHORIZATION_CODE_GRANT)
}
