use super::contract::test_support::{assert_referenced_slots, invocation_body};

#[test]
fn authorization_code_grant_commit_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let script = super::COMMIT_AUTHORIZATION_CODE_GRANT;
    assert_referenced_slots(
        script,
        "KEYS",
        &super::AUTHORIZATION_CODE_GRANT_COMMIT_KEY_PLAN,
    );
    assert_referenced_slots(
        script,
        "ARGV",
        &super::AUTHORIZATION_CODE_GRANT_COMMIT_ARG_PLAN,
    );

    let source = include_str!("../scripts.rs");
    let body = invocation_body(
        source,
        "fn invoke_authorization_code_grant_commit(",
        ".invoke::<String>(conn)",
    );
    assert!(body.contains("for key in keys.ordered()"));
    assert!(body.contains("for arg in args.ordered()"));
    assert_eq!(body.matches("invocation.key(key);").count(), 1);
    assert_eq!(
        body.matches("invocation.arg(").count(),
        3,
        "script args are applied by the typed RedisScriptArg dispatcher"
    );
}

#[test]
fn release_lock_script_deletes_only_matching_owner() {
    let script = super::RELEASE_LOCK_IF_OWNER;
    assert!(script.contains("redis.call('GET', KEYS[1]) == ARGV[1]"));
    assert!(script.contains("redis.call('DEL', KEYS[1])"));
    assert!(script.contains("return 0"));
}

#[test]
fn authorization_code_grant_commit_script_consumes_code_after_token_writes() {
    let script = super::COMMIT_AUTHORIZATION_CODE_GRANT;
    let set_access = script
        .find(r#"redis.call("SET", KEYS[4], ARGV[1])"#)
        .expect("script should store access token");
    let delete_code = script
        .find(r#"redis.call("DEL", KEYS[1])"#)
        .expect("script should delete authorization code");
    assert!(set_access < delete_code);
    assert!(script.contains(r#"return "missing_code""#));
    assert!(script.contains(r#"return "code_mismatch""#));
    assert!(script.contains(r#"redis.call("INCR", KEYS[2])"#));
    assert!(script.contains(r#"redis.call("INCR", KEYS[3])"#));
}

#[test]
fn authorization_code_grant_commit_script_decodes_before_writing() {
    let script = super::COMMIT_AUTHORIZATION_CODE_GRANT;
    let collision_error = script
        .find(r#"return "token_collision""#)
        .expect("script should fail closed on token key collisions");
    let decode_error = script
        .find(r#"return "refresh_children_decode""#)
        .expect("script should fail closed on malformed refresh children");
    let set_access = script
        .find(r#"redis.call("SET", KEYS[4], ARGV[1])"#)
        .expect("script should store access token");
    let set_refresh_children = script
        .find(r#"redis.call("SET", KEYS[10], refresh_children_payload)"#)
        .expect("script should write precomputed refresh children");

    assert!(collision_error < decode_error);
    assert!(decode_error < set_access);
    assert!(set_access < set_refresh_children);
}

#[test]
fn authorization_code_grant_commit_script_checks_token_collisions_before_side_effects() {
    let script = super::COMMIT_AUTHORIZATION_CODE_GRANT;
    let token_collision = script
        .find(r#"return "token_collision""#)
        .expect("script should fail closed on token key collisions");
    let code_mismatch = script
        .find(r#"return "code_mismatch""#)
        .expect("script should fail closed when code payload changes before commit");
    let oidc_cleanup = script
        .find("local function cleanup_oidc_sid")
        .expect("script should define OIDC cleanup after collision checks");
    let set_access = script
        .find(r#"redis.call("SET", KEYS[4], ARGV[1])"#)
        .expect("script should store access token");
    let delete_code = script
        .find(r#"redis.call("DEL", KEYS[1])"#)
        .expect("script should delete authorization code");

    assert!(code_mismatch < token_collision);
    assert!(token_collision < oidc_cleanup);
    assert!(token_collision < set_access);
    assert!(token_collision < delete_code);
}

#[test]
fn authorization_code_grant_commit_script_checks_oidc_before_token_writes() {
    let script = super::COMMIT_AUTHORIZATION_CODE_GRANT;
    let oidc_conflict = script
        .find(r#"return "oidc_session_conflict""#)
        .expect("script should fail closed on OIDC sid conflict");
    let oidc_collision = script
        .find(r#"return "oidc_session_collision""#)
        .expect("script should fail closed on OIDC sid collision");
    let set_access = script
        .find(r#"redis.call("SET", KEYS[4], ARGV[1])"#)
        .expect("script should store access token");

    assert!(oidc_conflict < set_access);
    assert!(oidc_collision < set_access);
}

#[test]
fn authorization_code_grant_commit_script_commits_oidc_before_code_consumption() {
    let script = super::COMMIT_AUTHORIZATION_CODE_GRANT;
    let oidc_session_write = script
        .find(r#""HSET", KEYS[15]"#)
        .expect("script should write OIDC session during grant commit");
    let oidc_client_write = script
        .find(r#"redis.call("SADD", KEYS[18], ARGV[20])"#)
        .expect("script should associate OIDC client during grant commit");
    let delete_code = script
        .find(r#"redis.call("DEL", KEYS[1])"#)
        .expect("script should delete authorization code");

    assert!(oidc_session_write < delete_code);
    assert!(oidc_client_write < delete_code);
}
