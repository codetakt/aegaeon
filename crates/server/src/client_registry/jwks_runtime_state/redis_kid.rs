use std::collections::HashMap;

use super::{JwksSharedStateError, RedisJwksRuntimeState};
use crate::client_registry::JwksRuntimePolicy;

const RECORD_KID_FINGERPRINTS_SCRIPT: &str = r#"-- Exact argument checks and optional ACL preflight for the shared JWKS ledger.
-- Required wire: one key; TTL text then at least one kid/fingerprint pair.
-- The Rust HashMap supplies unique kid identifiers.
local function bad(message)
  return redis.error_reply(message)
end

if #KEYS ~= 1 or type(KEYS[1]) ~= "string" or #ARGV < 3 or #ARGV % 2 ~= 1 then
  return bad("ERR invalid JWKS ledger argument shape")
end
local ttl = ARGV[1]
if type(ttl) ~= "string" or not string.match(ttl, "^[1-9][0-9]*$") then
  return bad("ERR invalid JWKS ledger TTL text")
end
for i = 2, #ARGV, 2 do
  if type(ARGV[i]) ~= "string" or type(ARGV[i + 1]) ~= "string" then
    return bad("ERR invalid JWKS ledger pair")
  end
end

-- Preserve the original conflict order and early return, including old engines.
for i = 2, #ARGV, 2 do
  local existing = redis.call("HGET", KEYS[1], ARGV[i])
  if existing and existing ~= ARGV[i + 1] then
    return 1
  end
end

-- Exact decimal byte comparison; no tonumber or locale-sensitive string order.
local largest_seconds = "9223372036854775"
local too_large = #ttl > #largest_seconds
if #ttl == #largest_seconds then
  for i = 1, #ttl do
    local given_byte = string.byte(ttl, i)
    local limit_byte = string.byte(largest_seconds, i)
    if given_byte ~= limit_byte then
      too_large = given_byte > limit_byte
      break
    end
  end
end
if too_large then
  return bad("ERR JWKS ledger TTL milliseconds overflow")
end

local check = rawget(redis, "acl_check_cmd")
if type(check) == "function" then
  for i = 2, #ARGV, 2 do
    if check("HSET", KEYS[1], ARGV[i], ARGV[i + 1]) ~= true then
      return bad("ERR JWKS ledger HSET permission preflight failed")
    end
  end
  if check("EXPIRE", KEYS[1], ttl) ~= true then
    return bad("ERR JWKS ledger EXPIRE permission preflight failed")
  end
elseif check ~= nil then
  return bad("ERR invalid JWKS ledger ACL capability")
end
-- Absent capability deliberately retains legacy compatibility and its known
-- EXPIRE-ACL residue: HSET may have completed before EXPIRE is denied.

for i = 2, #ARGV, 2 do
  redis.call("HSET", KEYS[1], ARGV[i], ARGV[i + 1])
end
if redis.call("EXPIRE", KEYS[1], ttl) ~= 1 then
  return bad("ERR unexpected JWKS ledger expiry reply")
end
return 0
"#;
#[cfg(test)]
const RECORD_KID_FINGERPRINTS_KEY_COUNT: usize = 1;
#[cfg(test)]
const RECORD_KID_FINGERPRINTS_FIXED_ARG_COUNT: usize = 1;

impl RedisJwksRuntimeState {
    pub(in crate::client_registry) fn record_kid_fingerprints(
        &self,
        policy: &JwksRuntimePolicy,
        uri: &str,
        kid_fps: &HashMap<String, String>,
    ) -> Result<bool, JwksSharedStateError> {
        if kid_fps.is_empty() {
            return Ok(false);
        }
        let key = self.key("kid-fps", uri);
        let ttl = Self::ttl_i64(policy)?;
        let script = redis::Script::new(RECORD_KID_FINGERPRINTS_SCRIPT);
        let mut invocation = script.prepare_invoke();
        invocation.key(key).arg(ttl);
        for (kid, fingerprint) in kid_fps {
            invocation.arg(kid).arg(fingerprint);
        }
        invocation
            .invoke::<redis::Value>(&mut self.connection()?)
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))
            .and_then(|value| decode_kid_ledger_reply(&value))
    }
}

fn decode_kid_ledger_reply(value: &redis::Value) -> Result<bool, JwksSharedStateError> {
    match value {
        redis::Value::Int(0) => Ok(false),
        redis::Value::Int(1) => Ok(true),
        _ => Err(JwksSharedStateError::BackendUnavailable(
            "unexpected JWKS kid-ledger reply".to_owned(),
        )),
    }
}

#[cfg(all(test, unix))]
mod behavior_tests;

#[cfg(all(test, unix))]
mod response_tests;

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

    #[test]
    fn record_kid_fingerprints_lua_contract_matches_dynamic_pair_invocation() {
        let source = include_str!("redis_kid.rs");
        let body = invocation_body(
            source,
            "pub(in crate::client_registry) fn record_kid_fingerprints(",
            ".invoke::<redis::Value>(",
        );
        assert_eq!(
            referenced_indexes(super::RECORD_KID_FINGERPRINTS_SCRIPT, "KEYS"),
            vec![1]
        );
        assert_eq!(
            referenced_indexes(super::RECORD_KID_FINGERPRINTS_SCRIPT, "ARGV"),
            vec![1]
        );
        assert_eq!(
            body.matches("invocation.key(").count(),
            super::RECORD_KID_FINGERPRINTS_KEY_COUNT
        );
        assert_eq!(
            body.matches(".arg(ttl)").count(),
            super::RECORD_KID_FINGERPRINTS_FIXED_ARG_COUNT
        );
        assert!(body.contains("for (kid, fingerprint) in kid_fps"));
        assert!(body.contains("invocation.arg(kid).arg(fingerprint);"));
        assert!(super::RECORD_KID_FINGERPRINTS_SCRIPT.contains("for i = 2, #ARGV, 2 do"));
    }
}
