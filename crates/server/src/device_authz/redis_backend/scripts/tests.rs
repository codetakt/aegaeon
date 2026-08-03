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
fn insert_entry_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis_backend.rs");
    let body = invocation_body(source, "pub(super) fn insert_entry(", ".invoke::<i64>(");
    assert_script_contract(
        super::INSERT_ENTRY,
        super::INSERT_ENTRY_KEY_COUNT,
        super::INSERT_ENTRY_ARG_COUNT,
        body,
    );
}

#[test]
fn poll_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis_backend.rs");
    let body = invocation_body(source, "pub(super) fn poll(", ".invoke::<Vec<String>>(");
    assert_script_contract(
        super::POLL,
        super::POLL_KEY_COUNT,
        super::POLL_ARG_COUNT,
        body,
    );
}

#[test]
fn transition_user_code_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis_backend.rs");
    let body = invocation_body(source, "fn transition_user_code(", ".invoke::<i64>(");
    assert_script_contract(
        super::TRANSITION_USER_CODE,
        super::TRANSITION_USER_CODE_KEY_COUNT,
        super::TRANSITION_USER_CODE_ARG_COUNT,
        body,
    );
}

#[test]
fn lookup_by_user_code_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis_backend.rs");
    let body = invocation_body(
        source,
        "pub(super) fn lookup_by_user_code(",
        ".invoke::<Option<Vec<String>>>(",
    );
    assert_script_contract(
        super::LOOKUP_BY_USER_CODE,
        super::LOOKUP_BY_USER_CODE_KEY_COUNT,
        super::LOOKUP_BY_USER_CODE_ARG_COUNT,
        body,
    );
}

#[test]
fn cleanup_expired_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis_backend.rs");
    let body = invocation_body(source, "pub(super) fn cleanup_expired(", ".invoke::<i64>(");
    assert_script_contract(
        super::CLEANUP_EXPIRED,
        super::CLEANUP_EXPIRED_KEY_COUNT,
        super::CLEANUP_EXPIRED_ARG_COUNT,
        body,
    );
}
