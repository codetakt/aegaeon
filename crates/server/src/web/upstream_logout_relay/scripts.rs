pub(super) const TAKE_RELAY: &str = r"
local payload = redis.call('GET', KEYS[1])
if payload then
  redis.call('DEL', KEYS[1])
end
return payload
";
#[cfg(test)]
const TAKE_RELAY_KEY_COUNT: usize = 1;
#[cfg(test)]
const TAKE_RELAY_ARG_COUNT: usize = 0;

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
    fn take_relay_lua_contract_is_contiguous_and_matches_rust_invocation() {
        let source = include_str!("../upstream_logout_relay.rs");
        let body = invocation_body(
            source,
            "fn take(\n        &self,",
            ".invoke::<Option<String>>(",
        );
        assert_script_contract(
            super::TAKE_RELAY,
            super::TAKE_RELAY_KEY_COUNT,
            super::TAKE_RELAY_ARG_COUNT,
            body,
        );
    }
}
