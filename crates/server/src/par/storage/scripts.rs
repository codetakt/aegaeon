const CONSUME_REQUEST_AND_RESERVATION: &str = r#"
local payload = redis.call("GET", KEYS[1])
if payload then
  redis.call("DEL", KEYS[1])
  redis.call("DEL", KEYS[2])
end
return payload
"#;

const RESERVE_REQUEST_IF_PRESENT: &str = r#"
if redis.call("EXISTS", KEYS[1]) == 0 then
  return 0
end
local reserved = redis.call("SET", KEYS[2], ARGV[1], "NX", "PX", ARGV[2])
if reserved then
  return 1
end
return 0
"#;

pub(super) fn consume_request_and_reservation_script() -> redis::Script {
    redis::Script::new(CONSUME_REQUEST_AND_RESERVATION)
}

pub(super) fn reserve_request_if_present_script() -> redis::Script {
    redis::Script::new(RESERVE_REQUEST_IF_PRESENT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn consume_script_deletes_request_and_reservation_after_read() {
        let script = super::CONSUME_REQUEST_AND_RESERVATION;
        assert!(script.contains(r#"redis.call("GET", KEYS[1])"#));
        assert!(script.contains(r#"redis.call("DEL", KEYS[1])"#));
        assert!(script.contains(r#"redis.call("DEL", KEYS[2])"#));
    }

    #[test]
    fn reserve_script_requires_request_before_reservation() {
        let script = super::RESERVE_REQUEST_IF_PRESENT;
        assert!(script.contains(r#"redis.call("EXISTS", KEYS[1])"#));
        assert!(script.contains(r#"redis.call("SET", KEYS[2], ARGV[1], "NX", "PX", ARGV[2])"#));
        assert!(script.contains("return 0"));
        assert!(script.contains("return 1"));
    }
}
