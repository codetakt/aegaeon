use super::*;

fn commit(conn: &mut redis::Connection, keys: &[String; 9]) -> redis::RedisResult<String> {
    invoke_store_code_if_absent(
        conn,
        StoreCodeIfAbsentKeys {
            code: &keys[0],
            state: &keys[1],
            nonce: &keys[2],
            version: &keys[3],
            state_index: &keys[4],
            nonce_index: &keys[5],
            par_request: &keys[6],
            par_reservation: &keys[7],
            request_object_jti: &keys[8],
        },
        StoreCodeIfAbsentArgs {
            payload: "exact repeated-value code",
            marker_ttl_ms: 60000,
            code_ttl_ms: 60000,
            has_state: true,
            has_nonce: true,
            state_value: "same-state",
            nonce_value: "same-nonce",
            marker_expires_at_epoch_ms: 2_000_000_000_000,
            has_par: true,
            has_request_object_jti: true,
            request_object_jti_ttl_ms: 60000,
            par_expected_continuation: "reserved",
        },
    )
}
fn reserve(conn: &mut redis::Connection, keys: &[String; 9]) {
    set(conn, &keys[6], b"PAR payload");
    set(conn, &keys[7], b"reserved");
}
fn another(keys: &[String; 9], suffix: &str) -> [String; 9] {
    let mut result = keys.clone();
    for i in [0, 6, 7, 8] {
        result[i] = format!("{}:{suffix}", keys[i]);
    }
    result
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn repeated_rp_values_refresh_markers_without_refunding_par_or_jti() {
    let mut conn = connection();
    let first = keys();
    reserve(&mut conn, &first);
    assert_eq!(commit(&mut conn, &first).unwrap(), "ok");
    for i in [1, 2] {
        redis::cmd("PEXPIRE")
            .arg(&first[i])
            .arg(2000)
            .query::<i64>(&mut conn)
            .unwrap();
        redis::cmd("ZADD")
            .arg(&first[i + 3])
            .arg(123)
            .arg(&first[i])
            .query::<i64>(&mut conn)
            .unwrap();
    }
    let second = another(&first, "second");
    reserve(&mut conn, &second);
    assert_eq!(commit(&mut conn, &second).unwrap(), "ok");
    for i in [1, 2] {
        let ttl: i64 = redis::cmd("PTTL").arg(&first[i]).query(&mut conn).unwrap();
        assert!(
            ttl > 50_000 && ttl <= 60_000,
            "last observation refresh: {ttl}"
        );
        let score: u64 = redis::cmd("ZSCORE")
            .arg(&first[i + 3])
            .arg(&first[i])
            .query(&mut conn)
            .unwrap();
        assert_eq!(score, 2_000_000_000_000);
        assert_eq!(
            redis::cmd("ZCARD")
                .arg(&first[i + 3])
                .query::<i64>(&mut conn)
                .unwrap(),
            1
        );
    }
    for record in [&first, &second] {
        assert_eq!(
            get(&mut conn, &record[0]).as_deref(),
            Some(b"exact repeated-value code".as_slice())
        );
        assert_eq!(get(&mut conn, &record[6]), None);
        assert_eq!(get(&mut conn, &record[7]), None);
        assert_eq!(get(&mut conn, &record[8]).as_deref(), Some(b"1".as_slice()));
    }
    assert_eq!(
        get(&mut conn, &first[1]).as_deref(),
        Some(b"same-state".as_slice())
    );
    assert_eq!(
        get(&mut conn, &first[2]).as_deref(),
        Some(b"same-nonce".as_slice())
    );
    let mut par_replay = another(&first, "par-replay");
    par_replay[6] = first[6].clone();
    par_replay[7] = first[7].clone();
    assert_eq!(commit(&mut conn, &par_replay).unwrap(), "par");
    assert_eq!(get(&mut conn, &par_replay[0]), None);
    assert_eq!(get(&mut conn, &par_replay[8]), None);
    let mut jti_replay = another(&first, "jti-replay");
    reserve(&mut conn, &jti_replay);
    jti_replay[8] = first[8].clone();
    assert_eq!(
        commit(&mut conn, &jti_replay).unwrap(),
        "request_object_jti"
    );
    assert_eq!(get(&mut conn, &jti_replay[0]), None);
    assert_eq!(
        get(&mut conn, &jti_replay[6]).as_deref(),
        Some(b"PAR payload".as_slice())
    );
    assert_eq!(get(&mut conn, &first[3]).as_deref(), Some(b"2".as_slice()));
    for record in [&first, &second, &par_replay, &jti_replay] {
        delete(&mut conn, record);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn repeated_rp_values_preflight_failure_preserves_code_par_jti_and_markers() {
    let mut conn = connection();
    for bad in [
        "overflow",
        "text",
        "version-type",
        "state-index",
        "nonce-index",
    ] {
        let keys = keys();
        reserve(&mut conn, &keys);
        set(&mut conn, &keys[1], b"previous-state");
        set(&mut conn, &keys[2], b"previous-nonce");
        let index = match bad {
            "state-index" => 4,
            "nonce-index" => 5,
            _ => 3,
        };
        match bad {
            "overflow" => set(&mut conn, &keys[3], b"9223372036854775807"),
            "text" => set(&mut conn, &keys[3], b"invalid-counter"),
            _ => {
                redis::cmd("HSET")
                    .arg(&keys[index])
                    .arg("fixture")
                    .arg("preserved")
                    .query::<i64>(&mut conn)
                    .unwrap();
            }
        }
        let before: Vec<u8> = redis::cmd("DUMP")
            .arg(&keys[index])
            .query(&mut conn)
            .unwrap();
        assert!(commit(&mut conn, &keys).is_err(), "{bad}");
        assert_eq!(get(&mut conn, &keys[0]), None);
        assert_eq!(get(&mut conn, &keys[8]), None);
        assert_eq!(
            get(&mut conn, &keys[6]).as_deref(),
            Some(b"PAR payload".as_slice())
        );
        assert_eq!(
            get(&mut conn, &keys[7]).as_deref(),
            Some(b"reserved".as_slice())
        );
        assert_eq!(
            get(&mut conn, &keys[1]).as_deref(),
            Some(b"previous-state".as_slice())
        );
        assert_eq!(
            get(&mut conn, &keys[2]).as_deref(),
            Some(b"previous-nonce".as_slice())
        );
        assert_eq!(
            redis::cmd("DUMP")
                .arg(&keys[index])
                .query::<Vec<u8>>(&mut conn)
                .unwrap(),
            before
        );
        delete(&mut conn, &keys);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL with ACL administration"]
fn repeated_rp_values_backend_denial_preserves_one_time_inputs() {
    let mut admin = connection();
    let keys = keys();
    reserve(&mut admin, &keys);
    set(&mut admin, &keys[1], b"previous-state");
    set(&mut admin, &keys[2], b"previous-nonce");
    let user = format!("authcode-repeat-{}", uuid::Uuid::new_v4());
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&user)
        .arg(&["reset", "on", "nopass", "+get", "~*"])
        .query::<()>(&mut admin)
        .unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut restricted = connection();
        redis::cmd("AUTH")
            .arg(&user)
            .arg("")
            .query::<()>(&mut restricted)
            .unwrap();
        let error = commit(&mut restricted, &keys).unwrap_err();
        assert_eq!(error.code(), Some("NOPERM"));
        assert_eq!(get(&mut admin, &keys[0]), None);
        assert_eq!(get(&mut admin, &keys[8]), None);
        assert_eq!(
            get(&mut admin, &keys[6]).as_deref(),
            Some(b"PAR payload".as_slice())
        );
        assert_eq!(
            get(&mut admin, &keys[7]).as_deref(),
            Some(b"reserved".as_slice())
        );
        assert_eq!(
            get(&mut admin, &keys[1]).as_deref(),
            Some(b"previous-state".as_slice())
        );
        assert_eq!(
            get(&mut admin, &keys[2]).as_deref(),
            Some(b"previous-nonce".as_slice())
        );
        assert_eq!(get(&mut admin, &keys[3]), None);
    }));
    delete(&mut admin, &keys);
    redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&user)
        .query::<usize>(&mut admin)
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
