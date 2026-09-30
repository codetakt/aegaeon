//! Actual Redis regressions for failures that previously occurred after writes.

use super::{invoke_store_code_if_absent, StoreCodeIfAbsentArgs, StoreCodeIfAbsentKeys};

fn connection() -> redis::Connection {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")
        .expect("Redis integration tests require AEGAEON_TEST_REDIS_URL");
    redis::Client::open(url).unwrap().get_connection().unwrap()
}

fn keys() -> [String; 9] {
    let prefix = format!("authcode-preflight:{{{}}}", uuid::Uuid::new_v4());
    std::array::from_fn(|index| format!("{prefix}:{index}"))
}

fn store(conn: &mut redis::Connection, keys: &[String; 9]) -> redis::RedisResult<String> {
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
            payload: "exact synthetic code",
            marker_ttl_ms: 60000,
            code_ttl_ms: 60000,
            has_state: true,
            has_nonce: true,
            state_value: "state",
            nonce_value: "nonce",
            marker_expires_at_epoch_ms: 2_000_000_000_000,
            has_par: false,
            has_request_object_jti: false,
            request_object_jti_ttl_ms: 60000,
            par_expected_continuation: "",
        },
    )
}

fn get(conn: &mut redis::Connection, key: &str) -> Option<Vec<u8>> {
    redis::cmd("GET").arg(key).query(conn).unwrap()
}

fn set(conn: &mut redis::Connection, key: &str, value: &[u8]) {
    redis::cmd("SET")
        .arg(key)
        .arg(value)
        .query::<()>(conn)
        .unwrap();
}

fn delete(conn: &mut redis::Connection, keys: &[String]) {
    redis::cmd("DEL").arg(keys).query::<usize>(conn).unwrap();
}

fn counter_samples() -> Vec<Option<Vec<u8>>> {
    let mut values = vec![None];
    for text in [
        "0",
        "1",
        "-1",
        "9223372036854775806",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775808",
        "-9223372036854775809",
        "9007199254740991",
        "9007199254740992",
        "9007199254740993",
        "-9007199254740991",
        "-9007199254740992",
        "-9007199254740993",
        "",
        "+0",
        "+1",
        "-0",
        "00",
        "01",
        "-01",
        "--1",
        " 1",
        "1 ",
        "1\n",
        "1.0",
        "1e0",
        "999999999999999999999999999999",
        "１",
    ] {
        values.push(Some(text.as_bytes().to_vec()));
    }
    values.push(Some(vec![0]));
    values.push(Some(vec![255]));
    values
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn increment_preflight_matches_redis_signed_integer_boundaries_without_partial_store() {
    let mut conn = connection();
    for value in counter_samples() {
        let keys = keys();
        let oracle_key = format!("{}:oracle", keys[3]);
        if let Some(value) = &value {
            set(&mut conn, &keys[3], value);
            set(&mut conn, &oracle_key, value);
        }
        let oracle: redis::RedisResult<i64> = redis::cmd("INCR").arg(&oracle_key).query(&mut conn);
        let result = store(&mut conn, &keys);
        assert_eq!(result.is_ok(), oracle.is_ok(), "counter sample: {value:?}");
        if let Ok(expected) = oracle {
            assert_eq!(result.unwrap(), "ok");
            assert_eq!(
                get(&mut conn, &keys[0]).as_deref(),
                Some(b"exact synthetic code".as_slice())
            );
            assert_eq!(
                get(&mut conn, &keys[3]),
                Some(expected.to_string().into_bytes())
            );
        } else {
            for key in &keys[..3] {
                assert_eq!(get(&mut conn, key), None);
            }
            assert_eq!(get(&mut conn, &keys[3]), value);
        }
        delete(&mut conn, &keys);
        delete(&mut conn, &[oracle_key]);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn invalid_counter_cannot_delete_a_code_during_consume() {
    let mut conn = connection();
    for value in counter_samples() {
        let keys = keys();
        let oracle_key = format!("{}:oracle", keys[3]);
        set(&mut conn, &keys[0], b"exact code to consume");
        if let Some(value) = &value {
            set(&mut conn, &keys[3], value);
            set(&mut conn, &oracle_key, value);
        }
        let oracle: redis::RedisResult<i64> = redis::cmd("INCR").arg(&oracle_key).query(&mut conn);
        let result = super::consume_code_script()
            .key(&keys[0])
            .key(&keys[3])
            .invoke::<Option<Vec<u8>>>(&mut conn);
        assert_eq!(result.is_ok(), oracle.is_ok(), "counter sample: {value:?}");
        if let Ok(expected) = oracle {
            assert_eq!(
                result.unwrap().as_deref(),
                Some(b"exact code to consume".as_slice())
            );
            assert_eq!(get(&mut conn, &keys[0]), None);
            assert_eq!(
                get(&mut conn, &keys[3]),
                Some(expected.to_string().into_bytes())
            );
        } else {
            assert_eq!(
                get(&mut conn, &keys[0]).as_deref(),
                Some(b"exact code to consume".as_slice())
            );
            assert_eq!(get(&mut conn, &keys[3]), value);
        }
        delete(&mut conn, &keys);
        delete(&mut conn, &[oracle_key]);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn invalid_version_or_index_type_is_detected_before_any_store_write() {
    let mut conn = connection();
    for bad_index in [3, 4, 5] {
        let keys = keys();
        redis::cmd("HSET")
            .arg(&keys[bad_index])
            .arg("fixture")
            .arg("value")
            .query::<usize>(&mut conn)
            .unwrap();
        assert!(store(&mut conn, &keys).is_err());
        for key in &keys[..3] {
            assert_eq!(get(&mut conn, key), None);
        }
        let value: String = redis::cmd("HGET")
            .arg(&keys[bad_index])
            .arg("fixture")
            .query(&mut conn)
            .unwrap();
        assert_eq!(value, "value");
        if bad_index != 3 {
            assert_eq!(get(&mut conn, &keys[3]), None);
        }
        delete(&mut conn, &keys);
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn invalid_version_type_cannot_delete_a_code_during_consume() {
    let mut conn = connection();
    let keys = keys();
    set(&mut conn, &keys[0], b"code with wrong-type counter");
    redis::cmd("HSET")
        .arg(&keys[3])
        .arg("fixture")
        .arg("value")
        .query::<usize>(&mut conn)
        .unwrap();
    assert!(super::consume_code_script()
        .key(&keys[0])
        .key(&keys[3])
        .invoke::<Option<Vec<u8>>>(&mut conn)
        .is_err());
    assert_eq!(
        get(&mut conn, &keys[0]).as_deref(),
        Some(b"code with wrong-type counter".as_slice())
    );
    let value: String = redis::cmd("HGET")
        .arg(&keys[3])
        .arg("fixture")
        .query(&mut conn)
        .unwrap();
    assert_eq!(value, "value");
    delete(&mut conn, &keys);
}
