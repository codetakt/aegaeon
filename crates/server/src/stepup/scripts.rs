pub(super) const ISSUE_CHALLENGE: &str = r#"
local id = ARGV[1]
local client_id = ARGV[2]
local session_id = ARGV[3]
local request_id = ARGV[4]
local issued_at = tonumber(ARGV[5])
local expires_at = tonumber(ARGV[6])
local retention_secs = tonumber(ARGV[7])
local now_epoch_secs = tonumber(ARGV[8])
local challenge_key_prefix = ARGV[9]
if not issued_at or not expires_at or not retention_secs or retention_secs < 1 then
  return redis.error_reply("invalid step-up challenge timestamps")
end
if not now_epoch_secs then
  return redis.error_reply("invalid step-up cleanup time")
end

local function cleanup_id(stale_id)
  local stale_challenge_key = challenge_key_prefix .. stale_id
  local stale_request_key = redis.call("HGET", stale_challenge_key, "request_redis_key")
  redis.call("DEL", stale_challenge_key)
  if stale_request_key then
    redis.call("DEL", stale_request_key)
  end
  redis.call("ZREM", KEYS[3], stale_id)
end

local expired = redis.call("ZRANGEBYSCORE", KEYS[3], "-inf", now_epoch_secs)
for _, stale_id in ipairs(expired) do
  cleanup_id(stale_id)
end

local previous_id = redis.call("GET", KEYS[2])
if previous_id then
  cleanup_id(previous_id)
end

redis.call(
  "HSET", KEYS[1],
  "id", id,
  "client_id", client_id,
  "session_id", session_id,
  "request_id", request_id,
  "issued_at_epoch_secs", issued_at,
  "expires_at_epoch_secs", expires_at,
  "completed", "0",
  "request_redis_key", KEYS[2]
)
redis.call("EXPIRE", KEYS[1], retention_secs)
redis.call("SET", KEYS[2], id, "EX", retention_secs)
redis.call("ZADD", KEYS[3], expires_at, id)
return 1
"#;
#[cfg(test)]
const ISSUE_CHALLENGE_KEY_COUNT: usize = 3;
#[cfg(test)]
const ISSUE_CHALLENGE_ARG_COUNT: usize = 9;

pub(super) const COMPLETE_FOR_REQUEST: &str = r#"
local challenge_id = redis.call("GET", KEYS[1])
if not challenge_id then
  return nil
end
local challenge_key = ARGV[2] .. challenge_id
local values = redis.call(
  "HMGET", challenge_key,
  "id", "client_id", "session_id", "request_id",
  "issued_at_epoch_secs", "expires_at_epoch_secs", "completed"
)
if not values[1] then
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], challenge_id)
  return nil
end
local now_epoch_secs = tonumber(ARGV[1])
local issued_at = tonumber(values[5])
local expires_at = tonumber(values[6])
if not now_epoch_secs or not issued_at or not expires_at then
  return redis.error_reply("invalid step-up challenge record")
end
if expires_at <= now_epoch_secs then
  redis.call("DEL", challenge_key)
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], challenge_id)
  return nil
end
if issued_at > now_epoch_secs or values[7] ~= "0" then
  return nil
end
redis.call("HSET", challenge_key, "completed", "1")
values[7] = "1"
return values
"#;
#[cfg(test)]
const COMPLETE_FOR_REQUEST_KEY_COUNT: usize = 2;
#[cfg(test)]
const COMPLETE_FOR_REQUEST_ARG_COUNT: usize = 2;

pub(super) const CONSUME_COMPLETED: &str = r#"
local challenge_id = redis.call("GET", KEYS[1])
if not challenge_id then
  return 0
end
local challenge_key = ARGV[2] .. challenge_id
local values = redis.call(
  "HMGET", challenge_key,
  "issued_at_epoch_secs", "expires_at_epoch_secs", "completed"
)
if not values[1] then
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], challenge_id)
  return 0
end
local now_epoch_secs = tonumber(ARGV[1])
local issued_at = tonumber(values[1])
local expires_at = tonumber(values[2])
if not now_epoch_secs or not issued_at or not expires_at then
  return redis.error_reply("invalid step-up challenge record")
end
if expires_at <= now_epoch_secs then
  redis.call("DEL", challenge_key)
  redis.call("DEL", KEYS[1])
  redis.call("ZREM", KEYS[2], challenge_id)
  return 0
end
if issued_at > now_epoch_secs or values[3] ~= "1" then
  return 0
end
redis.call("DEL", challenge_key)
redis.call("DEL", KEYS[1])
redis.call("ZREM", KEYS[2], challenge_id)
return 1
"#;
#[cfg(test)]
const CONSUME_COMPLETED_KEY_COUNT: usize = 2;
#[cfg(test)]
const CONSUME_COMPLETED_ARG_COUNT: usize = 2;

pub(super) const CLEANUP_EXPIRED: &str = r#"
local expired = redis.call("ZRANGEBYSCORE", KEYS[1], "-inf", ARGV[1])
for _, challenge_id in ipairs(expired) do
  local challenge_key = ARGV[2] .. challenge_id
  local request_key = redis.call("HGET", challenge_key, "request_redis_key")
  redis.call("DEL", challenge_key)
  if request_key then
    redis.call("DEL", request_key)
  end
  redis.call("ZREM", KEYS[1], challenge_id)
end
return #expired
"#;
#[cfg(test)]
const CLEANUP_EXPIRED_KEY_COUNT: usize = 1;
#[cfg(test)]
const CLEANUP_EXPIRED_ARG_COUNT: usize = 2;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    fn referenced_indexes(script: &str, prefix: &str) -> Vec<usize> {
        let marker = format!("{prefix}[");
        script
            .match_indices(&marker)
            .filter_map(|(offset, _)| {
                let start = offset + marker.len();
                let digits: String = script[start..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_digit())
                    .collect();
                digits.parse::<usize>().ok()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn expected_indexes(len: usize) -> Vec<usize> {
        (1..=len).collect()
    }

    fn invocation_body<'a>(source: &'a str, name: &str, invoke_marker: &str) -> &'a str {
        let start = source
            .find(name)
            .expect("script invocation function should exist");
        let rest = &source[start..];
        let end = rest
            .find(invoke_marker)
            .expect("script invocation should end with Redis invoke");
        &rest[..end]
    }

    fn assert_script_contract(script: &str, key_count: usize, arg_count: usize, body: &str) {
        assert_eq!(
            referenced_indexes(script, "KEYS"),
            expected_indexes(key_count)
        );
        assert_eq!(
            referenced_indexes(script, "ARGV"),
            expected_indexes(arg_count)
        );
        assert_eq!(body.matches(".key(").count(), key_count);
        assert_eq!(body.matches(".arg(").count(), arg_count);
    }

    #[test]
    fn issue_challenge_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("redis_backend.rs");
        let body = invocation_body(source, "pub(super) fn issue_challenge(", ".invoke::<i64>(");
        assert_script_contract(
            super::ISSUE_CHALLENGE,
            super::ISSUE_CHALLENGE_KEY_COUNT,
            super::ISSUE_CHALLENGE_ARG_COUNT,
            body,
        );
    }

    #[test]
    fn complete_for_request_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("redis_backend.rs");
        let body = invocation_body(
            source,
            "pub(super) fn complete_for_request(",
            ".invoke::<Option<Vec<String>>>(",
        );
        assert_script_contract(
            super::COMPLETE_FOR_REQUEST,
            super::COMPLETE_FOR_REQUEST_KEY_COUNT,
            super::COMPLETE_FOR_REQUEST_ARG_COUNT,
            body,
        );
    }

    #[test]
    fn consume_completed_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("redis_backend.rs");
        let body = invocation_body(
            source,
            "pub(super) fn consume_completed(",
            ".invoke::<i64>(",
        );
        assert_script_contract(
            super::CONSUME_COMPLETED,
            super::CONSUME_COMPLETED_KEY_COUNT,
            super::CONSUME_COMPLETED_ARG_COUNT,
            body,
        );
    }

    #[test]
    fn cleanup_expired_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("redis_backend.rs");
        let body = invocation_body(source, "pub(super) fn cleanup_expired(", ".invoke::<i64>(");
        assert_script_contract(
            super::CLEANUP_EXPIRED,
            super::CLEANUP_EXPIRED_KEY_COUNT,
            super::CLEANUP_EXPIRED_ARG_COUNT,
            body,
        );
    }
}
