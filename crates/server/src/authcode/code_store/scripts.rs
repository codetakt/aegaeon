const STORE_CODE_IF_ABSENT: &str = r#"
if ARGV[4] == "1" and redis.call("EXISTS", KEYS[2]) == 1 then
  return "state"
end
if ARGV[5] == "1" and redis.call("EXISTS", KEYS[3]) == 1 then
  return "nonce"
end
if redis.call("EXISTS", KEYS[1]) == 1 then
  return "code"
end
if ARGV[9] == "1" and redis.call("EXISTS", KEYS[7]) == 0 then
  return "par"
end
if ARGV[9] == "1" and redis.call("GET", KEYS[8]) ~= ARGV[12] then
  return "par"
end
if ARGV[10] == "1" and redis.call("EXISTS", KEYS[9]) == 1 then
  return "request_object_jti"
end
if ARGV[4] == "1" then
  redis.call("SET", KEYS[2], ARGV[6], "PX", ARGV[2])
  redis.call("ZADD", KEYS[5], ARGV[8], KEYS[2])
end
if ARGV[5] == "1" then
  redis.call("SET", KEYS[3], ARGV[7], "PX", ARGV[2])
  redis.call("ZADD", KEYS[6], ARGV[8], KEYS[3])
end
redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[3])
if ARGV[9] == "1" then
  redis.call("DEL", KEYS[7])
  redis.call("DEL", KEYS[8])
end
if ARGV[10] == "1" then
  redis.call("SET", KEYS[9], "1", "NX", "PX", ARGV[11])
end
redis.call("INCR", KEYS[4])
return "ok"
"#;
#[cfg(test)]
const STORE_CODE_IF_ABSENT_KEY_COUNT: usize = 9;
#[cfg(test)]
const STORE_CODE_IF_ABSENT_ARG_COUNT: usize = 12;

const CONSUME_CODE: &str = r#"
local payload = redis.call("GET", KEYS[1])
if payload then
  redis.call("DEL", KEYS[1])
  redis.call("INCR", KEYS[2])
end
return payload
"#;

const RELEASE_LOCK_IF_OWNER: &str = r"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
";

pub(super) struct StoreCodeIfAbsentKeys<'a> {
    pub(super) code: &'a str,
    pub(super) state: &'a str,
    pub(super) nonce: &'a str,
    pub(super) version: &'a str,
    pub(super) state_index: &'a str,
    pub(super) nonce_index: &'a str,
    pub(super) par_request: &'a str,
    pub(super) par_reservation: &'a str,
    pub(super) request_object_jti: &'a str,
}

pub(super) struct StoreCodeIfAbsentArgs<'a> {
    pub(super) payload: &'a str,
    pub(super) marker_ttl_ms: i64,
    pub(super) code_ttl_ms: i64,
    pub(super) has_state: bool,
    pub(super) has_nonce: bool,
    pub(super) state_value: &'a str,
    pub(super) nonce_value: &'a str,
    pub(super) marker_expires_at_epoch_ms: u64,
    pub(super) has_par: bool,
    pub(super) has_request_object_jti: bool,
    pub(super) request_object_jti_ttl_ms: i64,
    pub(super) par_expected_continuation: &'a str,
}

fn redis_bool(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

pub(super) fn invoke_store_code_if_absent(
    conn: &mut redis::Connection,
    keys: StoreCodeIfAbsentKeys<'_>,
    args: StoreCodeIfAbsentArgs<'_>,
) -> redis::RedisResult<String> {
    store_code_if_absent_script()
        .key(keys.code)
        .key(keys.state)
        .key(keys.nonce)
        .key(keys.version)
        .key(keys.state_index)
        .key(keys.nonce_index)
        .key(keys.par_request)
        .key(keys.par_reservation)
        .key(keys.request_object_jti)
        .arg(args.payload)
        .arg(args.marker_ttl_ms)
        .arg(args.code_ttl_ms)
        .arg(redis_bool(args.has_state))
        .arg(redis_bool(args.has_nonce))
        .arg(args.state_value)
        .arg(args.nonce_value)
        .arg(args.marker_expires_at_epoch_ms)
        .arg(redis_bool(args.has_par))
        .arg(redis_bool(args.has_request_object_jti))
        .arg(args.request_object_jti_ttl_ms)
        .arg(args.par_expected_continuation)
        .invoke::<String>(conn)
}

pub(super) fn store_code_if_absent_script() -> redis::Script {
    redis::Script::new(STORE_CODE_IF_ABSENT)
}

pub(super) fn consume_code_script() -> redis::Script {
    redis::Script::new(CONSUME_CODE)
}

pub(super) fn release_lock_if_owner_script() -> redis::Script {
    redis::Script::new(RELEASE_LOCK_IF_OWNER)
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
            .find(".invoke::<String>(conn)")
            .expect("script invocation should end with Redis invoke");
        &rest[..end]
    }

    #[test]
    fn store_code_if_absent_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let script = super::STORE_CODE_IF_ABSENT;
        assert_eq!(
            referenced_indexes(script, "KEYS"),
            expected_indexes(super::STORE_CODE_IF_ABSENT_KEY_COUNT)
        );
        assert_eq!(
            referenced_indexes(script, "ARGV"),
            expected_indexes(super::STORE_CODE_IF_ABSENT_ARG_COUNT)
        );

        let source = include_str!("scripts.rs");
        let body = invocation_body(source, "fn invoke_store_code_if_absent(");
        assert_eq!(
            body.matches(".key(").count(),
            super::STORE_CODE_IF_ABSENT_KEY_COUNT
        );
        assert_eq!(
            body.matches(".arg(").count(),
            super::STORE_CODE_IF_ABSENT_ARG_COUNT
        );
    }

    #[test]
    fn store_script_checks_state_nonce_and_code_before_set() {
        let script = super::STORE_CODE_IF_ABSENT;
        assert!(script.contains(r#"redis.call("EXISTS", KEYS[2])"#));
        assert!(script.contains(r#"redis.call("EXISTS", KEYS[3])"#));
        assert!(script.contains(r#"redis.call("EXISTS", KEYS[1])"#));
        assert!(script.contains(r#"redis.call("EXISTS", KEYS[7])"#));
        assert!(script.contains(r#"redis.call("GET", KEYS[8]) ~= ARGV[12]"#));
        assert!(script.contains(r#"redis.call("EXISTS", KEYS[9])"#));
        assert!(script.contains(r#"redis.call("ZADD", KEYS[5], ARGV[8], KEYS[2])"#));
        assert!(script.contains(r#"redis.call("ZADD", KEYS[6], ARGV[8], KEYS[3])"#));
        assert!(script.contains(r#"redis.call("INCR", KEYS[4])"#));
    }

    #[test]
    fn store_script_consumes_one_time_inputs_after_code_write() {
        let script = super::STORE_CODE_IF_ABSENT;
        let par_missing = script
            .find(r#"return "par""#)
            .expect("script should fail closed when PAR is missing");
        let request_object_replay = script
            .find(r#"return "request_object_jti""#)
            .expect("script should fail closed when request object jti is replayed");
        let set_code = script
            .find(r#"redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[3])"#)
            .expect("script should write code");
        let delete_par = script
            .find(r#"redis.call("DEL", KEYS[7])"#)
            .expect("script should consume PAR request");
        let set_jti = script
            .find(r#"redis.call("SET", KEYS[9], "1", "NX", "PX", ARGV[11])"#)
            .expect("script should consume request object jti");

        assert!(par_missing < set_code);
        assert!(request_object_replay < set_code);
        assert!(set_code < delete_par);
        assert!(set_code < set_jti);
    }

    #[test]
    fn consume_script_deletes_code_and_bumps_version() {
        let script = super::CONSUME_CODE;
        assert!(script.contains(r#"redis.call("GET", KEYS[1])"#));
        assert!(script.contains(r#"redis.call("DEL", KEYS[1])"#));
        assert!(script.contains(r#"redis.call("INCR", KEYS[2])"#));
    }

    #[test]
    fn release_lock_script_deletes_only_matching_owner() {
        let script = super::RELEASE_LOCK_IF_OWNER;
        assert!(script.contains("redis.call('GET', KEYS[1]) == ARGV[1]"));
        assert!(script.contains("redis.call('DEL', KEYS[1])"));
        assert!(script.contains("return 0"));
    }
}
