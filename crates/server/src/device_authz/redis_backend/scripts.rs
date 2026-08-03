pub(super) const INSERT_ENTRY: &str = r#"
local hash = ARGV[1]
local lookup = ARGV[2]
local client_id = ARGV[3]
local scope_present = ARGV[4]
local scope = ARGV[5]
local resource_present = ARGV[6]
local resource = ARGV[7]
local environment_present = ARGV[8]
local environment_id = ARGV[9]
local status = ARGV[10]
local approved_user_id = ARGV[11]
local expires_at_ms = tonumber(ARGV[12])
local retention_ms = tonumber(ARGV[13])
local poll_interval_secs = tonumber(ARGV[14])
local now_ms = tonumber(ARGV[15])
local entry_key_prefix = ARGV[16]
local user_key_prefix = ARGV[17]
if not expires_at_ms or not retention_ms or retention_ms < 1 then
  return redis.error_reply("invalid device code expiry")
end
if not poll_interval_secs then
  return redis.error_reply("invalid device code poll interval")
end
if not now_ms then
  return redis.error_reply("invalid device code cleanup time")
end

local function cleanup_hash(stale_hash)
  local stale_entry_key = entry_key_prefix .. stale_hash
  local stale_lookup_key = redis.call("HGET", stale_entry_key, "user_code_lookup_key")
  redis.call("DEL", stale_entry_key)
  if stale_lookup_key then
    redis.call("DEL", user_key_prefix .. stale_lookup_key)
  end
  redis.call("ZREM", KEYS[3], stale_hash)
end

local expired = redis.call("ZRANGEBYSCORE", KEYS[3], "-inf", now_ms)
for _, stale_hash in ipairs(expired) do
  cleanup_hash(stale_hash)
end

if redis.call("EXISTS", KEYS[1]) == 1 or redis.call("EXISTS", KEYS[2]) == 1 then
  return 0
end

redis.call(
  "HSET", KEYS[1],
  "device_code_hash", hash,
  "user_code_lookup_key", lookup,
  "client_id", client_id,
  "scope_present", scope_present,
  "scope", scope,
  "resource_present", resource_present,
  "resource", resource,
  "environment_id_present", environment_present,
  "environment_id", environment_id,
  "status", status,
  "approved_user_id", approved_user_id,
  "expires_at_ms", expires_at_ms,
  "last_poll_at_ms", "",
  "poll_interval_secs", poll_interval_secs,
  "consumed", "0"
)
redis.call("PEXPIRE", KEYS[1], retention_ms)
redis.call("SET", KEYS[2], hash, "PX", retention_ms)
redis.call("ZADD", KEYS[3], expires_at_ms, hash)
return 1
"#;
#[cfg(test)]
const INSERT_ENTRY_KEY_COUNT: usize = 3;
#[cfg(test)]
const INSERT_ENTRY_ARG_COUNT: usize = 17;

pub(super) const POLL: &str = r#"
local client_id = ARGV[1]
local environment_present = ARGV[2]
local environment_id = ARGV[3]
local requested_resource_present = ARGV[4]
local requested_resource = ARGV[5]
local now_ms = tonumber(ARGV[6])
local slow_down_increment = tonumber(ARGV[7])
local hash = ARGV[8]
local entry_key_prefix = ARGV[9]
local user_key_prefix = ARGV[10]
if not now_ms or not slow_down_increment then
  return redis.error_reply("invalid device poll arguments")
end

local function cleanup_hash(stale_hash)
  local stale_entry_key = entry_key_prefix .. stale_hash
  local stale_lookup_key = redis.call("HGET", stale_entry_key, "user_code_lookup_key")
  redis.call("DEL", stale_entry_key)
  if stale_lookup_key then
    redis.call("DEL", user_key_prefix .. stale_lookup_key)
  end
  redis.call("ZREM", KEYS[2], stale_hash)
end

if redis.call("EXISTS", KEYS[1]) == 0 then
  redis.call("ZREM", KEYS[2], hash)
  return {"expired_token"}
end

local values = redis.call(
  "HMGET", KEYS[1],
  "client_id", "environment_id_present", "environment_id",
  "resource_present", "resource", "expires_at_ms",
  "last_poll_at_ms", "poll_interval_secs", "status",
  "approved_user_id", "scope_present", "scope", "consumed"
)
local expires_at_ms = tonumber(values[6])
local poll_interval_secs = tonumber(values[8])
if not expires_at_ms or not poll_interval_secs then
  return redis.error_reply("invalid device code record")
end

if values[1] ~= client_id
  or values[2] ~= environment_present
  or (environment_present == "1" and values[3] ~= environment_id) then
  return {"expired_token"}
end

if now_ms >= expires_at_ms then
  cleanup_hash(hash)
  return {"expired_token"}
end

if values[4] == "1" then
  if requested_resource_present == "1" and values[5] ~= requested_resource then
    return {"invalid_target"}
  end
elseif requested_resource_present == "1" then
  return {"invalid_target"}
end

if values[7] and values[7] ~= "" then
  local last_poll_at_ms = tonumber(values[7])
  if not last_poll_at_ms then
    return redis.error_reply("invalid device code poll timestamp")
  end
  if now_ms - last_poll_at_ms < poll_interval_secs * 1000 then
    redis.call("HSET", KEYS[1], "poll_interval_secs", poll_interval_secs + slow_down_increment)
    redis.call("HSET", KEYS[1], "last_poll_at_ms", now_ms)
    return {"slow_down"}
  end
end
redis.call("HSET", KEYS[1], "last_poll_at_ms", now_ms)

if values[9] == "pending" then
  return {"authorization_pending"}
elseif values[9] == "denied" then
  cleanup_hash(hash)
  return {"access_denied"}
elseif values[9] == "approved" then
  if values[13] == "1" then
    cleanup_hash(hash)
    return {"expired_token"}
  end
  cleanup_hash(hash)
  return {"approved", values[10], values[11], values[12], values[4], values[5], values[1]}
else
  cleanup_hash(hash)
  return {"expired_token"}
end
"#;
#[cfg(test)]
const POLL_KEY_COUNT: usize = 2;
#[cfg(test)]
const POLL_ARG_COUNT: usize = 10;

pub(super) const TRANSITION_USER_CODE: &str = r#"
local now_ms = tonumber(ARGV[1])
local next_status = ARGV[2]
local approved_user_id = ARGV[3]
local entry_key_prefix = ARGV[4]
if not now_ms then
  return redis.error_reply("invalid device code transition time")
end
local hash = redis.call("GET", KEYS[1])
if not hash then
  return 0
end
local entry_key = entry_key_prefix .. hash
local status = redis.call("HGET", entry_key, "status")
if not status then
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], hash)
  return 0
end
local expires_at_ms = tonumber(redis.call("HGET", entry_key, "expires_at_ms"))
if not expires_at_ms then
  return redis.error_reply("invalid device code expiry")
end
if now_ms >= expires_at_ms then
  redis.call("DEL", entry_key)
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], hash)
  return 0
end
if status ~= "pending" then
  return 0
end
redis.call("HSET", entry_key, "status", next_status)
redis.call("HSET", entry_key, "approved_user_id", approved_user_id)
return 1
"#;
#[cfg(test)]
const TRANSITION_USER_CODE_KEY_COUNT: usize = 2;
#[cfg(test)]
const TRANSITION_USER_CODE_ARG_COUNT: usize = 4;

pub(super) const LOOKUP_BY_USER_CODE: &str = r#"
local now_ms = tonumber(ARGV[1])
local entry_key_prefix = ARGV[2]
if not now_ms then
  return redis.error_reply("invalid device code lookup time")
end
local hash = redis.call("GET", KEYS[1])
if not hash then
  return nil
end
local entry_key = entry_key_prefix .. hash
local values = redis.call(
  "HMGET", entry_key,
  "client_id", "scope_present", "scope", "resource_present",
  "resource", "expires_at_ms", "status"
)
if not values[1] then
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], hash)
  return nil
end
local expires_at_ms = tonumber(values[6])
if not expires_at_ms then
  return redis.error_reply("invalid device code expiry")
end
if now_ms >= expires_at_ms then
  redis.call("DEL", entry_key)
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], hash)
  return nil
end
if values[7] ~= "pending" then
  return nil
end
return {values[1], values[2], values[3], values[4], values[5]}
"#;
#[cfg(test)]
const LOOKUP_BY_USER_CODE_KEY_COUNT: usize = 2;
#[cfg(test)]
const LOOKUP_BY_USER_CODE_ARG_COUNT: usize = 2;

pub(super) const CLEANUP_EXPIRED: &str = r#"
local now_ms = tonumber(ARGV[1])
local entry_key_prefix = ARGV[2]
local user_key_prefix = ARGV[3]
if not now_ms then
  return redis.error_reply("invalid device code cleanup time")
end
local expired = redis.call("ZRANGEBYSCORE", KEYS[1], "-inf", now_ms)
for _, hash in ipairs(expired) do
  local entry_key = entry_key_prefix .. hash
  local lookup = redis.call("HGET", entry_key, "user_code_lookup_key")
  redis.call("DEL", entry_key)
  if lookup then
    redis.call("DEL", user_key_prefix .. lookup)
  end
  redis.call("ZREM", KEYS[1], hash)
end
return #expired
"#;
#[cfg(test)]
const CLEANUP_EXPIRED_KEY_COUNT: usize = 1;
#[cfg(test)]
const CLEANUP_EXPIRED_ARG_COUNT: usize = 3;

#[cfg(test)]
#[path = "scripts/tests.rs"]
mod tests;
