use super::{CircuitPhase, JwksSharedStateError, RedisJwksRuntimeState};
use crate::client_registry::JwksRuntimePolicy;

const CIRCUIT_ALLOW_FETCH_SCRIPT: &str = r#"
local phase = redis.call("HGET", KEYS[1], "phase")
if (not phase) or phase == "closed" then
  redis.call("HSET", KEYS[1], "phase", "closed", "failures", "0", "opened_at_ms", "0", "probe", "0")
  redis.call("EXPIRE", KEYS[1], ARGV[3])
  return "closed"
end
if phase == "open" then
  local opened = tonumber(redis.call("HGET", KEYS[1], "opened_at_ms") or "0")
  if opened > 0 and (tonumber(ARGV[1]) - opened) >= tonumber(ARGV[2]) then
    redis.call("HSET", KEYS[1], "phase", "half_open", "probe", "1")
    redis.call("EXPIRE", KEYS[1], ARGV[3])
    return "half_open"
  end
  return "deny"
end
if phase == "half_open" then
  local probe = redis.call("HGET", KEYS[1], "probe")
  if probe == "1" then
    return "deny"
  end
  redis.call("HSET", KEYS[1], "probe", "1")
  redis.call("EXPIRE", KEYS[1], ARGV[3])
  return "half_open"
end
redis.call("HSET", KEYS[1], "phase", "closed", "failures", "0", "opened_at_ms", "0", "probe", "0")
redis.call("EXPIRE", KEYS[1], ARGV[3])
return "closed"
"#;
#[cfg(test)]
const CIRCUIT_ALLOW_FETCH_KEY_COUNT: usize = 1;
#[cfg(test)]
const CIRCUIT_ALLOW_FETCH_ARG_COUNT: usize = 3;

const CIRCUIT_ON_FAILURE_SCRIPT: &str = r#"
local phase = redis.call("HGET", KEYS[1], "phase") or "closed"
local failures = tonumber(redis.call("HGET", KEYS[1], "failures") or "0") + 1
local opened = redis.call("HGET", KEYS[1], "opened_at_ms") or "0"
local next_phase = phase
if phase == "half_open" then
  next_phase = "open"
  opened = ARGV[1]
elseif phase == "open" then
  next_phase = "open"
  if opened == "0" then
    opened = ARGV[1]
  end
elseif failures >= tonumber(ARGV[2]) then
  next_phase = "open"
  opened = ARGV[1]
end
redis.call("HSET", KEYS[1], "phase", next_phase, "failures", failures, "opened_at_ms", opened, "probe", "0")
redis.call("EXPIRE", KEYS[1], ARGV[3])
return next_phase
"#;
#[cfg(test)]
const CIRCUIT_ON_FAILURE_KEY_COUNT: usize = 1;
#[cfg(test)]
const CIRCUIT_ON_FAILURE_ARG_COUNT: usize = 3;

impl RedisJwksRuntimeState {
    pub(in crate::client_registry) fn circuit_allow_fetch(
        &self,
        policy: &JwksRuntimePolicy,
        uri: &str,
    ) -> Result<CircuitPhase, JwksSharedStateError> {
        let key = self.key("circuit", uri);
        let now_ms = Self::now_epoch_millis_i64()?;
        let reset_ms = policy
            .circuit_reset_secs
            .checked_mul(1000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(JwksSharedStateError::RetentionOverflow)?;
        let ttl = Self::ttl_i64(policy)?;
        let phase = redis::Script::new(CIRCUIT_ALLOW_FETCH_SCRIPT)
            .key(key)
            .arg(now_ms)
            .arg(reset_ms)
            .arg(ttl)
            .invoke::<String>(&mut self.connection()?)
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))?;
        if phase == "deny" {
            return Ok(CircuitPhase::Open);
        }
        Ok(CircuitPhase::from_redis_str(&phase))
    }

    pub(in crate::client_registry) fn circuit_on_success(
        &self,
        policy: &JwksRuntimePolicy,
        uri: &str,
    ) -> Result<(), JwksSharedStateError> {
        let key = self.key("circuit", uri);
        let mut conn = self.connection()?;
        redis::cmd("HSET")
            .arg(&key)
            .arg("phase")
            .arg(CircuitPhase::Closed.as_redis_str())
            .arg("failures")
            .arg(0)
            .arg("opened_at_ms")
            .arg(0)
            .arg("probe")
            .arg(0)
            .query::<redis::Value>(&mut conn)
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))?;
        redis::cmd("EXPIRE")
            .arg(&key)
            .arg(Self::ttl_i64(policy)?)
            .query::<redis::Value>(&mut conn)
            .map(|_| ())
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))
    }

    pub(in crate::client_registry) fn circuit_on_failure(
        &self,
        policy: &JwksRuntimePolicy,
        uri: &str,
    ) -> Result<CircuitPhase, JwksSharedStateError> {
        let key = self.key("circuit", uri);
        let now_ms = Self::now_epoch_millis_i64()?;
        let ttl = Self::ttl_i64(policy)?;
        let phase = redis::Script::new(CIRCUIT_ON_FAILURE_SCRIPT)
            .key(key)
            .arg(now_ms)
            .arg(policy.circuit_open_fails)
            .arg(ttl)
            .invoke::<String>(&mut self.connection()?)
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))?;
        Ok(CircuitPhase::from_redis_str(&phase))
    }

    #[cfg(any(test, kani))]
    pub(in crate::client_registry) fn circuit_phase(
        &self,
        uri: &str,
    ) -> Result<CircuitPhase, JwksSharedStateError> {
        let key = self.key("circuit", uri);
        redis::cmd("HGET")
            .arg(key)
            .arg("phase")
            .query::<Option<String>>(&mut self.connection()?)
            .map(|phase| {
                phase
                    .as_deref()
                    .map_or(CircuitPhase::Closed, CircuitPhase::from_redis_str)
            })
            .map_err(|err| JwksSharedStateError::BackendUnavailable(err.to_string()))
    }
}

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

    fn invocation_body<'a>(source: &'a str, name: &str) -> &'a str {
        let start = source
            .find(name)
            .expect("script invocation function should exist");
        let rest = &source[start..];
        let end = rest
            .find(".invoke::<String>(")
            .expect("script invocation should end with Redis invoke");
        &rest[..end]
    }

    fn chained_invocation_count(body: &str, method: &str) -> usize {
        body.lines()
            .filter(|line| line.trim_start().starts_with(method))
            .count()
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
        assert_eq!(chained_invocation_count(body, ".key("), key_count);
        assert_eq!(chained_invocation_count(body, ".arg("), arg_count);
    }

    #[test]
    fn circuit_allow_fetch_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("redis_circuit.rs");
        let body = invocation_body(
            source,
            "pub(in crate::client_registry) fn circuit_allow_fetch(",
        );
        assert_script_contract(
            super::CIRCUIT_ALLOW_FETCH_SCRIPT,
            super::CIRCUIT_ALLOW_FETCH_KEY_COUNT,
            super::CIRCUIT_ALLOW_FETCH_ARG_COUNT,
            body,
        );
    }

    #[test]
    fn circuit_on_failure_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("redis_circuit.rs");
        let body = invocation_body(
            source,
            "pub(in crate::client_registry) fn circuit_on_failure(",
        );
        assert_script_contract(
            super::CIRCUIT_ON_FAILURE_SCRIPT,
            super::CIRCUIT_ON_FAILURE_KEY_COUNT,
            super::CIRCUIT_ON_FAILURE_ARG_COUNT,
            body,
        );
    }
}
