use aegaeon_crypto::hash::Sha256Hasher;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

const RATE_LIMIT_REDIS_KEY_PREFIX: &str = "rate-limit:v1";
const CHECK_ALL_SCRIPT: &str = r#"
local max_attempts = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
if not max_attempts or max_attempts < 0 then
  return redis.error_reply("invalid max attempts")
end
if not window_ms or window_ms < 1 then
  return redis.error_reply("invalid window")
end

for i = 1, #KEYS do
  local current = redis.call("GET", KEYS[i])
  local next_count = 1
  if current then
    local count = tonumber(current)
    if not count then
      return redis.error_reply("invalid counter")
    end
    next_count = count + 1
  end
  if next_count > max_attempts then
    return 0
  end
end

for i = 1, #KEYS do
  local current = redis.call("GET", KEYS[i])
  if current then
    local count = tonumber(current)
    if not count then
      return redis.error_reply("invalid counter")
    end
    redis.call("SET", KEYS[i], count + 1, "KEEPTTL")
    if redis.call("PTTL", KEYS[i]) < 0 then
      redis.call("PEXPIRE", KEYS[i], window_ms)
    end
  else
    redis.call("SET", KEYS[i], 1, "PX", window_ms)
  end
end

return 1
"#;
#[cfg(test)]
const CHECK_ALL_SCRIPT_ARG_COUNT: usize = 2;

pub(super) struct RedisVerificationRateLimiter {
    pub(super) namespace: Arc<str>,
    client: redis::Client,
}

#[derive(Debug, Error)]
pub(super) enum VerificationRateLimiterError {
    #[error("verification rate limiter backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("verification rate limiter window cannot be represented")]
    RetentionOverflow,
}

impl RedisVerificationRateLimiter {
    pub(super) fn new(
        url: &str,
        namespace: impl Into<Arc<str>>,
    ) -> Result<Self, VerificationRateLimiterError> {
        redis::Client::open(url)
            .map(|client| Self {
                client,
                namespace: namespace.into(),
            })
            .map_err(|err| VerificationRateLimiterError::BackendUnavailable(err.to_string()))
    }

    fn connection(&self) -> Result<redis::Connection, VerificationRateLimiterError> {
        self.client
            .get_connection()
            .map_err(|err| VerificationRateLimiterError::BackendUnavailable(err.to_string()))
    }

    fn key(&self, bucket: &str) -> String {
        let mut hasher = Sha256Hasher::new();
        hasher.update(b"aegaeon:rate-limit:v1");
        hasher.update(&(self.namespace.len() as u64).to_be_bytes());
        hasher.update(self.namespace.as_bytes());
        hasher.update(&(bucket.len() as u64).to_be_bytes());
        hasher.update(bucket.as_bytes());
        format!(
            "{RATE_LIMIT_REDIS_KEY_PREFIX}:{{{}}}:{}",
            self.namespace,
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        )
    }

    pub(super) fn check_all(
        &self,
        buckets: &[&str],
        max_attempts: u32,
        window: Duration,
    ) -> Result<bool, VerificationRateLimiterError> {
        if buckets.is_empty() {
            return Ok(true);
        }
        let window_ms = rate_limit_window_millis_i64(window)?;
        let keys = buckets
            .iter()
            .map(|bucket| self.key(bucket))
            .collect::<Vec<_>>();
        let script = redis::Script::new(CHECK_ALL_SCRIPT);
        let mut invocation = script.prepare_invoke();
        keys.iter().for_each(|key| {
            invocation.key(key);
        });
        invocation
            .arg(i64::from(max_attempts))
            .arg(window_ms)
            .invoke::<i64>(&mut self.connection()?)
            .map(|value| value == 1)
            .map_err(|err| VerificationRateLimiterError::BackendUnavailable(err.to_string()))
    }
}

fn rate_limit_window_millis_i64(window: Duration) -> Result<i64, VerificationRateLimiterError> {
    window
        .as_millis()
        .try_into()
        .map(|window_ms: i64| window_ms.max(1))
        .map_err(|_| VerificationRateLimiterError::RetentionOverflow)
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
    fn check_all_lua_contract_uses_dynamic_keys_and_fixed_arguments() {
        let source = include_str!("redis_backend.rs");
        let body = invocation_body(source, "pub(super) fn check_all(", ".invoke::<i64>(");
        assert_eq!(
            referenced_indexes(super::CHECK_ALL_SCRIPT, "KEYS"),
            Vec::<usize>::new()
        );
        assert_eq!(
            referenced_indexes(super::CHECK_ALL_SCRIPT, "ARGV"),
            vec![1, 2]
        );
        assert!(super::CHECK_ALL_SCRIPT.contains("for i = 1, #KEYS do"));
        assert!(body.contains("keys.iter().for_each(|key|"));
        assert_eq!(body.matches("invocation.key(").count(), 1);
        assert_eq!(
            body.matches(".arg(").count(),
            super::CHECK_ALL_SCRIPT_ARG_COUNT
        );
    }
}
