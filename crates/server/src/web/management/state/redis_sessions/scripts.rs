pub(super) const CREATE_SESSION: &str = r#"
            local sid = ARGV[1]
            local payload = ARGV[2]
            local created_at = tonumber(ARGV[3])
            local expires_at = tonumber(ARGV[4])
            local retention_secs = tonumber(ARGV[5])
            local max_sessions = tonumber(ARGV[6])
            local now_epoch_secs = tonumber(ARGV[7])
            local session_key_prefix = ARGV[8]
            if not created_at or not expires_at or not retention_secs or retention_secs < 1 then
              return redis.error_reply("invalid management session timestamps")
            end
            if not max_sessions or max_sessions < 1 then
              return redis.error_reply("invalid management session capacity")
            end
            if not now_epoch_secs then
              return redis.error_reply("invalid management session cleanup time")
            end

            local function cleanup_sid(stale_sid)
              redis.call("DEL", session_key_prefix .. stale_sid)
              redis.call("ZREM", KEYS[2], stale_sid)
              redis.call("ZREM", KEYS[3], stale_sid)
            end

            local expired = redis.call("ZRANGEBYSCORE", KEYS[3], "-inf", now_epoch_secs)
            for _, stale_sid in ipairs(expired) do
              cleanup_sid(stale_sid)
            end

            while redis.call("ZCARD", KEYS[2]) >= max_sessions do
              local oldest = redis.call("ZRANGE", KEYS[2], 0, 0)
              if not oldest[1] then
                break
              end
              cleanup_sid(oldest[1])
            end

            redis.call("SET", KEYS[1], payload, "EX", retention_secs)
            redis.call("ZADD", KEYS[2], created_at, sid)
            redis.call("ZADD", KEYS[3], expires_at, sid)
            return 1
            "#;
#[cfg(test)]
const CREATE_SESSION_KEY_COUNT: usize = 3;
#[cfg(test)]
const CREATE_SESSION_ARG_COUNT: usize = 8;

pub(super) const DELETE_SESSION: &str = r#"
            local removed = redis.call("DEL", KEYS[1])
            redis.call("ZREM", KEYS[2], ARGV[1])
            redis.call("ZREM", KEYS[3], ARGV[1])
            return removed
            "#;
#[cfg(test)]
const DELETE_SESSION_KEY_COUNT: usize = 3;
#[cfg(test)]
const DELETE_SESSION_ARG_COUNT: usize = 1;

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
            .find(".invoke::<i64>(")
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
    fn create_session_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("operations/session/create.rs");
        let body = invocation_body(source, "pub(in crate::web::management::state) fn create(");
        assert_script_contract(
            super::CREATE_SESSION,
            super::CREATE_SESSION_KEY_COUNT,
            super::CREATE_SESSION_ARG_COUNT,
            body,
        );
    }

    #[test]
    fn delete_session_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("operations/session/delete.rs");
        let body = invocation_body(source, "fn delete_sid_with_conn(");
        assert_script_contract(
            super::DELETE_SESSION,
            super::DELETE_SESSION_KEY_COUNT,
            super::DELETE_SESSION_ARG_COUNT,
            body,
        );
    }
}
