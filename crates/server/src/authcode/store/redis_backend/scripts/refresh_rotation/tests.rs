use super::super::contract::test_support::{assert_referenced_slots, invocation_body};

#[test]
fn refresh_rotation_commit_lua_contract_is_contiguous_and_matches_rust_invocation() {
    let script = super::COMMIT_REFRESH_ROTATION;
    assert_referenced_slots(script, "KEYS", &super::REFRESH_ROTATION_COMMIT_KEY_PLAN);
    assert_referenced_slots(script, "ARGV", &super::REFRESH_ROTATION_COMMIT_ARG_PLAN);

    let source = include_str!("../refresh_rotation.rs");
    let body = invocation_body(
        source,
        "fn invoke_refresh_rotation_commit(",
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
fn refresh_rotation_commit_script_honors_mutation_barrier_before_reads() {
    let script = super::COMMIT_REFRESH_ROTATION;
    let barrier = script
        .find(r#"redis.call("EXISTS", KEYS[1]) == 1"#)
        .expect("script should check global mutation barrier");
    let load_previous = script
        .find(r#"redis.call("GET", KEYS[2])"#)
        .expect("script should load previous refresh token");

    assert!(barrier < load_previous);
    assert!(script.contains(r#"return "busy""#));
}

#[test]
fn refresh_rotation_commit_script_checks_expected_payload_before_writes() {
    let script = super::COMMIT_REFRESH_ROTATION;
    let stale = script
        .find(r#"return "stale""#)
        .expect("script should reject stale expected payloads");
    let first_write = script
        .find(r#"redis.call("SET", KEYS[2], ARGV[4])"#)
        .expect("script should set the rotated previous refresh payload");

    assert!(stale < first_write);
    assert_eq!(
        script
            .matches(r#"redis.call("SET", KEYS[2], ARGV[4])"#)
            .count(),
        1
    );
}

#[test]
fn refresh_rotation_commit_script_checks_collisions_before_token_writes() {
    let script = super::COMMIT_REFRESH_ROTATION;
    let collision = script
        .find(r#"return "token_collision""#)
        .expect("script should fail closed on token key collisions");
    let set_new_refresh = script
        .find(r#"redis.call("SET", KEYS[9], ARGV[5])"#)
        .expect("script should store the successor refresh token");
    let set_access = script
        .find(r#"redis.call("SET", KEYS[14], ARGV[12])"#)
        .expect("script should store access token when committing a grant");
    let set_bearer = script
        .find(r#"redis.call("SET", KEYS[17], ARGV[15])"#)
        .expect("script should store bearer metadata when committing a grant");
    let index_bearer = script
        .find(r#"redis.call("ZADD", KEYS[19], ARGV[17], ARGV[16])"#)
        .expect("script should index bearer metadata expiry");

    assert!(collision < set_new_refresh);
    assert!(collision < set_access);
    assert!(collision < set_bearer);
    assert!(set_bearer < index_bearer);
}

#[test]
fn refresh_rotation_commit_script_deindexes_expired_previous_refresh() {
    let script = super::COMMIT_REFRESH_ROTATION;
    let deindex_subject = script
        .find(r#"redis.call("SREM", KEYS[10], ARGV[2])"#)
        .expect("script should remove expired previous refresh from its subject index");
    let deindex_expiry = script
        .find(r#"redis.call("ZREM", KEYS[12], ARGV[2])"#)
        .expect("script should remove expired previous refresh from its expiry index");
    let expired = script
        .find(r#"return "expired""#)
        .expect("script should report expired previous refresh");

    assert!(deindex_subject < expired);
    assert!(deindex_expiry < expired);
}

#[test]
fn refresh_rotation_commit_script_treats_corrupt_revoked_payload_as_storage_error() {
    let script = super::COMMIT_REFRESH_ROTATION;
    let decode_revoked = script
        .find(r#"local ok, revoked = pcall(cjson.decode, revoked_payload)"#)
        .expect("script should decode stored revoked payloads");
    let revoked_decode = script[decode_revoked..]
        .find(r#"return "refresh_decode""#)
        .map(|offset| decode_revoked + offset)
        .expect("script should classify corrupt revoked payloads as codec errors");
    let revoked_active_invalid = script
        .find(r#"if revoked_expires_at > now_epoch_secs then"#)
        .expect("script should reject actively revoked refresh tokens");

    assert!(decode_revoked < revoked_decode);
    assert!(revoked_decode < revoked_active_invalid);
}
