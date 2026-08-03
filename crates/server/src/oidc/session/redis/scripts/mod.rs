pub(super) const GET_OR_CREATE_SESSION: &str = r#"
local user_id = ARGV[1]
local auth_session_key = ARGV[2]
local user_sessions_key = ARGV[3]
local new_sid = ARGV[4]
local now_epoch_secs = tonumber(ARGV[5])
local ttl_secs = tonumber(ARGV[6])
local session_key_prefix = ARGV[7]
local clients_key_prefix = ARGV[8]
if not now_epoch_secs or not ttl_secs or ttl_secs < 1 then
  return redis.error_reply("invalid OIDC logout session creation arguments")
end

local function cleanup_sid(sid)
  local session_key = session_key_prefix .. sid
  local clients_key = clients_key_prefix .. sid
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
  redis.call("ZREM", KEYS[3], sid)
end

local function logged_out_expired(logged_out_at_text)
  local logged_out_at = tonumber(logged_out_at_text)
  if not logged_out_at then
    return true
  end
  return logged_out_at > now_epoch_secs or now_epoch_secs - logged_out_at >= ttl_secs
end

local current_sid = redis.call("GET", KEYS[1])
if current_sid then
  local current_session_key = session_key_prefix .. current_sid
  local values = redis.call(
    "HMGET", current_session_key,
    "user_id", "auth_session_key", "user_sessions_key", "logout_jti", "logged_out_at_epoch_secs"
  )
  if values[1] and values[2] and values[3] and values[4] and values[5]
    and values[2] == auth_session_key and values[3] == user_sessions_key and values[1] == user_id then
    if values[4] == "" and values[5] == "" then
      return current_sid
    end
    if values[4] ~= "" and values[5] ~= "" and not logged_out_expired(values[5]) then
      redis.call("DEL", KEYS[1])
    else
      cleanup_sid(current_sid)
    end
  elseif not values[1] or not values[2] or not values[3] or not values[4] or not values[5] then
    cleanup_sid(current_sid)
  else
    if values[2] == auth_session_key then
      cleanup_sid(current_sid)
    else
      redis.call("DEL", KEYS[1])
    end
  end
end

if redis.call("EXISTS", KEYS[2]) == 1 then
  return redis.error_reply("OIDC logout session id collision")
end

redis.call(
  "HSET", KEYS[2],
  "user_id", user_id,
  "auth_session_key", auth_session_key,
  "user_sessions_key", user_sessions_key,
  "logout_jti", "",
  "logged_out_at_epoch_secs", ""
)
redis.call("SET", KEYS[1], new_sid)
redis.call("SADD", KEYS[4], new_sid)
return new_sid
"#;
#[cfg(test)]
const GET_OR_CREATE_SESSION_KEY_COUNT: usize = 4;
#[cfg(test)]
const GET_OR_CREATE_SESSION_ARG_COUNT: usize = 8;

pub(super) const ADD_CLIENT: &str = r#"
local sid = ARGV[1]
local client_id = ARGV[2]
local now_epoch_secs = tonumber(ARGV[3])
local ttl_secs = tonumber(ARGV[4])
if not now_epoch_secs or not ttl_secs or ttl_secs < 1 then
  return redis.error_reply("invalid OIDC logout session client arguments")
end

local function cleanup_sid()
  local auth_session_key = redis.call("HGET", KEYS[1], "auth_session_key")
  local user_sessions_key = redis.call("HGET", KEYS[1], "user_sessions_key")
  if auth_session_key and redis.call("GET", auth_session_key) == sid then
    redis.call("DEL", auth_session_key)
  end
  if user_sessions_key then
    redis.call("SREM", user_sessions_key, sid)
    if redis.call("SCARD", user_sessions_key) == 0 then
      redis.call("DEL", user_sessions_key)
    end
  end
  redis.call("DEL", KEYS[1])
  redis.call("DEL", KEYS[2])
  redis.call("ZREM", KEYS[3], sid)
end

local values = redis.call(
  "HMGET", KEYS[1],
  "logout_jti", "logged_out_at_epoch_secs", "auth_session_key", "user_sessions_key"
)
if not values[1] or not values[2] or not values[3] or not values[4]
  or values[3] == "" or values[4] == "" then
  cleanup_sid()
  return 0
end
if values[1] == "" and values[2] == "" then
  redis.call("SADD", KEYS[2], client_id)
  return 1
end
if values[1] == "" or values[2] == "" then
  cleanup_sid()
  return 0
end

local logged_out_at = tonumber(values[2])
if not logged_out_at or logged_out_at > now_epoch_secs or now_epoch_secs - logged_out_at >= ttl_secs then
  cleanup_sid()
end
return 0
"#;
#[cfg(test)]
const ADD_CLIENT_KEY_COUNT: usize = 3;
#[cfg(test)]
const ADD_CLIENT_ARG_COUNT: usize = 4;

pub(super) const LOGOUT_BY_SID: &str = r#"
local sid = ARGV[1]
local now_epoch_secs = tonumber(ARGV[2])
local ttl_secs = tonumber(ARGV[3])
local new_jti = ARGV[4]
local expiry_score = tonumber(ARGV[5])
if not now_epoch_secs or not ttl_secs or ttl_secs < 1 or not expiry_score then
  return redis.error_reply("invalid OIDC logout session logout arguments")
end

local function cleanup_sid()
  local auth_session_key = redis.call("HGET", KEYS[1], "auth_session_key")
  local user_sessions_key = redis.call("HGET", KEYS[1], "user_sessions_key")
  if auth_session_key and redis.call("GET", auth_session_key) == sid then
    redis.call("DEL", auth_session_key)
  end
  if user_sessions_key then
    redis.call("SREM", user_sessions_key, sid)
    if redis.call("SCARD", user_sessions_key) == 0 then
      redis.call("DEL", user_sessions_key)
    end
  end
  redis.call("DEL", KEYS[1])
  redis.call("DEL", KEYS[2])
  redis.call("ZREM", KEYS[3], sid)
end

local function event(user_id, jti)
  local clients = redis.call("SMEMBERS", KEYS[2])
  local response = {sid, user_id, jti}
  for _, client_id in ipairs(clients) do
    table.insert(response, client_id)
  end
  return response
end

local values = redis.call(
  "HMGET", KEYS[1],
  "user_id", "auth_session_key", "user_sessions_key", "logout_jti", "logged_out_at_epoch_secs"
)
if not values[1] or not values[2] or not values[3] or not values[4] or not values[5]
  or values[1] == "" or values[2] == "" or values[3] == "" then
  cleanup_sid()
  return nil
end

if values[4] ~= "" then
  if values[5] == "" then
    cleanup_sid()
    return nil
  end
  local logged_out_at = tonumber(values[5])
  if not logged_out_at or logged_out_at > now_epoch_secs or now_epoch_secs - logged_out_at >= ttl_secs then
    cleanup_sid()
    return nil
  end
  return event(values[1], values[4])
end

if values[5] ~= "" then
  cleanup_sid()
  return nil
end

redis.call(
  "HSET", KEYS[1],
  "logout_jti", new_jti,
  "logged_out_at_epoch_secs", now_epoch_secs
)
redis.call("EXPIRE", KEYS[1], ttl_secs)
redis.call("EXPIRE", KEYS[2], ttl_secs)
redis.call("ZADD", KEYS[3], expiry_score, sid)
if redis.call("GET", values[2]) == sid then
  redis.call("DEL", values[2])
end
redis.call("SREM", values[3], sid)
if redis.call("SCARD", values[3]) == 0 then
  redis.call("DEL", values[3])
end
return event(values[1], new_jti)
"#;
#[cfg(test)]
const LOGOUT_BY_SID_KEY_COUNT: usize = 3;
#[cfg(test)]
const LOGOUT_BY_SID_ARG_COUNT: usize = 5;

pub(super) const DELETE_AUTH_SESSION_ALIAS_IF_CURRENT: &str = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0
"#;
#[cfg(test)]
const DELETE_AUTH_SESSION_ALIAS_IF_CURRENT_KEY_COUNT: usize = 1;
#[cfg(test)]
const DELETE_AUTH_SESSION_ALIAS_IF_CURRENT_ARG_COUNT: usize = 1;

pub(super) const LOGOUT_BY_USER: &str = r#"
local requested_user_id = ARGV[1]
local now_epoch_secs = tonumber(ARGV[2])
local ttl_secs = tonumber(ARGV[3])
local new_jti_prefix = ARGV[4]
local expiry_score = tonumber(ARGV[5])
local session_key_prefix = ARGV[6]
local clients_key_prefix = ARGV[7]
if not now_epoch_secs or not ttl_secs or ttl_secs < 1 or not expiry_score then
  return redis.error_reply("invalid OIDC logout session user logout arguments")
end

local function cleanup_sid(sid)
  local session_key = session_key_prefix .. sid
  local clients_key = clients_key_prefix .. sid
  local auth_session_key = redis.call("HGET", session_key, "auth_session_key")
  local user_sessions_key = redis.call("HGET", session_key, "user_sessions_key")
  if auth_session_key and redis.call("GET", auth_session_key) == sid then
    redis.call("DEL", auth_session_key)
  end
  if user_sessions_key then
    redis.call("SREM", user_sessions_key, sid)
  end
  redis.call("SREM", KEYS[1], sid)
  redis.call("DEL", session_key)
  redis.call("DEL", clients_key)
  redis.call("ZREM", KEYS[2], sid)
end

local function event(sid, clients_key, user_id, jti)
  local clients = redis.call("SMEMBERS", clients_key)
  local response = {sid, user_id, jti}
  for _, client_id in ipairs(clients) do
    table.insert(response, client_id)
  end
  return response
end

local responses = {}
local sids = redis.call("SMEMBERS", KEYS[1])
local issued = 0
for _, sid in ipairs(sids) do
  local session_key = session_key_prefix .. sid
  local clients_key = clients_key_prefix .. sid
  local values = redis.call(
    "HMGET", session_key,
    "user_id", "auth_session_key", "user_sessions_key", "logout_jti", "logged_out_at_epoch_secs"
  )
  if not values[1] or not values[2] or not values[3] or not values[4] or not values[5]
    or values[1] == "" or values[2] == "" or values[3] ~= KEYS[1] then
    cleanup_sid(sid)
  elseif values[1] ~= requested_user_id then
    redis.call("SREM", KEYS[1], sid)
  elseif values[4] ~= "" then
    if values[5] == "" then
      cleanup_sid(sid)
    else
      local logged_out_at = tonumber(values[5])
      if not logged_out_at or logged_out_at > now_epoch_secs or now_epoch_secs - logged_out_at >= ttl_secs then
        cleanup_sid(sid)
      else
        table.insert(responses, event(sid, clients_key, values[1], values[4]))
      end
    end
  elseif values[5] ~= "" then
    cleanup_sid(sid)
  else
    issued = issued + 1
    local new_jti = new_jti_prefix .. ":" .. tostring(issued)
    redis.call(
      "HSET", session_key,
      "logout_jti", new_jti,
      "logged_out_at_epoch_secs", now_epoch_secs
    )
    redis.call("EXPIRE", session_key, ttl_secs)
    redis.call("EXPIRE", clients_key, ttl_secs)
    redis.call("ZADD", KEYS[2], expiry_score, sid)
    if redis.call("GET", values[2]) == sid then
      redis.call("DEL", values[2])
    end
    redis.call("SREM", KEYS[1], sid)
    table.insert(responses, event(sid, clients_key, values[1], new_jti))
  end
end

if redis.call("SCARD", KEYS[1]) == 0 then
  redis.call("DEL", KEYS[1])
end

return responses
"#;
#[cfg(test)]
const LOGOUT_BY_USER_KEY_COUNT: usize = 2;
#[cfg(test)]
const LOGOUT_BY_USER_ARG_COUNT: usize = 7;

pub(super) const CLEANUP_EXPIRED: &str = r#"
local now_epoch_secs = tonumber(ARGV[1])
local ttl_secs = tonumber(ARGV[2])
local future_cutoff = tonumber(ARGV[3])
local session_key_prefix = ARGV[4]
local clients_key_prefix = ARGV[5]
if not now_epoch_secs or not ttl_secs or ttl_secs < 1 or not future_cutoff then
  return redis.error_reply("invalid OIDC logout session cleanup arguments")
end

local function cleanup_sid(sid)
  local session_key = session_key_prefix .. sid
  local clients_key = clients_key_prefix .. sid
  local auth_session_key = redis.call("HGET", session_key, "auth_session_key")
  local user_sessions_key = redis.call("HGET", session_key, "user_sessions_key")
  if auth_session_key and redis.call("GET", auth_session_key) == sid then
    redis.call("DEL", auth_session_key)
  end
  if user_sessions_key then
    redis.call("SREM", user_sessions_key, sid)
    if redis.call("SCARD", user_sessions_key) == 0 then
      redis.call("DEL", user_sessions_key)
    end
  end
  redis.call("DEL", session_key)
  redis.call("DEL", clients_key)
  redis.call("ZREM", KEYS[1], sid)
end

local removed = 0
local expired = redis.call("ZRANGEBYSCORE", KEYS[1], "-inf", now_epoch_secs)
for _, sid in ipairs(expired) do
  cleanup_sid(sid)
  removed = removed + 1
end

local future = redis.call("ZRANGEBYSCORE", KEYS[1], "(" .. future_cutoff, "+inf")
for _, sid in ipairs(future) do
  cleanup_sid(sid)
  removed = removed + 1
end

return removed
"#;
#[cfg(test)]
const CLEANUP_EXPIRED_KEY_COUNT: usize = 1;
#[cfg(test)]
const CLEANUP_EXPIRED_ARG_COUNT: usize = 5;

#[cfg(test)]
mod tests;
