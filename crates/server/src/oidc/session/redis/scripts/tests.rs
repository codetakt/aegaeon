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
fn get_or_create_session_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis.rs");
    let body = invocation_body(
        source,
        "pub(super) fn get_or_create_session(",
        ".invoke::<String>(",
    );
    assert_script_contract(
        super::GET_OR_CREATE_SESSION,
        super::GET_OR_CREATE_SESSION_KEY_COUNT,
        super::GET_OR_CREATE_SESSION_ARG_COUNT,
        body,
    );
}

#[test]
fn add_client_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis.rs");
    let body = invocation_body(source, "pub(super) fn add_client(", ".invoke::<i64>(");
    assert_script_contract(
        super::ADD_CLIENT,
        super::ADD_CLIENT_KEY_COUNT,
        super::ADD_CLIENT_ARG_COUNT,
        body,
    );
}

#[test]
fn logout_by_sid_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis.rs");
    let body = invocation_body(
        source,
        "pub(super) fn logout_by_sid_at(",
        ".invoke::<Option<Vec<String>>>(",
    );
    assert_script_contract(
        super::LOGOUT_BY_SID,
        super::LOGOUT_BY_SID_KEY_COUNT,
        super::LOGOUT_BY_SID_ARG_COUNT,
        body,
    );
}

#[test]
fn delete_auth_session_alias_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis.rs");
    let body = invocation_body(
        source,
        "redis::Script::new(scripts::DELETE_AUTH_SESSION_ALIAS_IF_CURRENT)",
        ".invoke::<i64>(",
    );
    assert_script_contract(
        super::DELETE_AUTH_SESSION_ALIAS_IF_CURRENT,
        super::DELETE_AUTH_SESSION_ALIAS_IF_CURRENT_KEY_COUNT,
        super::DELETE_AUTH_SESSION_ALIAS_IF_CURRENT_ARG_COUNT,
        body,
    );
}

#[test]
fn logout_by_user_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../../redis.rs");
    let body = invocation_body(
        source,
        "pub(super) fn logout_by_user_at(",
        ".invoke::<Vec<Vec<String>>>(",
    );
    assert_script_contract(
        super::LOGOUT_BY_USER,
        super::LOGOUT_BY_USER_KEY_COUNT,
        super::LOGOUT_BY_USER_ARG_COUNT,
        body,
    );
}

#[test]
fn cleanup_expired_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let source = include_str!("../maintenance.rs");
    let body = invocation_body(
        source,
        "pub(super) fn cleanup_expired_with_conn(",
        ".invoke::<i64>(",
    );
    assert_script_contract(
        super::CLEANUP_EXPIRED,
        super::CLEANUP_EXPIRED_KEY_COUNT,
        super::CLEANUP_EXPIRED_ARG_COUNT,
        body,
    );
}
