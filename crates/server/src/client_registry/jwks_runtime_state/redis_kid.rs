use std::collections::HashMap;

use super::{JwksSharedStateError, RedisJwksRuntimeState};
use crate::client_registry::JwksRuntimePolicy;

const RECORD_KID_FINGERPRINTS_SCRIPT: &str = r#"
for i = 2, #ARGV, 2 do
  local existing = redis.call("HGET", KEYS[1], ARGV[i])
  if existing and existing ~= ARGV[i + 1] then
    return 1
  end
end
for i = 2, #ARGV, 2 do
  redis.call("HSET", KEYS[1], ARGV[i], ARGV[i + 1])
end
redis.call("EXPIRE", KEYS[1], ARGV[1])
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
            .invoke::<i32>(&mut self.connection()?)
            .map(|value| value == 1)
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
            ".invoke::<i32>(",
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
