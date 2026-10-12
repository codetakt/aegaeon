//! Isolate the Redis commit-time root guard with synthetic script inputs.
//! Normal issuance caps refresh expiry at the root deadline, so these inputs
//! deliberately do not represent an ordinarily issued grant.

use super::{invoke_refresh_rotation_commit, RefreshRotationCommitArgs, RefreshRotationCommitKeys};

fn commit(
    conn: &mut redis::Connection,
    keys: &[String; 21],
    previous: &str,
    now: u64,
    refresh_deadline: u64,
    root_deadline: u64,
) -> redis::RedisResult<String> {
    invoke_refresh_rotation_commit(
        conn,
        &super::super::super::refresh_grants::GrantCommit::independent_for_test(&keys[19]),
        RefreshRotationCommitKeys {
            mutation_barrier: &keys[0],
            previous_refresh: &keys[1],
            previous_revoked: &keys[2],
            revoked_expiry: &keys[3],
            previous_children: &keys[4],
            previous_successor: &keys[5],
            previous_predecessor: &keys[6],
            new_predecessor: &keys[7],
            new_refresh: &keys[8],
            previous_subject_refresh: &keys[9],
            subject_refresh: &keys[10],
            refresh_expiry: &keys[11],
            new_children: &keys[12],
            access: &keys[13],
            subject_access: &keys[14],
            access_expiry: &keys[15],
            bearer: &keys[16],
            subject_bearer: &keys[17],
            bearer_expiry: &keys[18],
            version: &keys[19],
            exchange_root_revoked: &keys[20],
        },
        RefreshRotationCommitArgs {
            now_epoch_secs: now,
            has_exchange_root: true,
            exchange_root_deadline_epoch_secs: root_deadline,
            exchange_root_deadline_nanos: 0,
            previous_refresh_token: "previous-refresh",
            expected_previous_payload: previous,
            rotated_previous_payload: "rotated-previous",
            new_refresh_payload: "new-refresh-payload",
            new_refresh_token: "new-refresh",
            new_refresh_expires_at_epoch_secs: refresh_deadline,
            successor_payload: "successor",
            predecessor_payload: "predecessor",
            new_children_payload: "new-children",
            has_grant: true,
            access_payload: "new-access-payload",
            access_token: "new-access",
            access_expires_at_epoch_secs: refresh_deadline,
            bearer_payload: "new-bearer-payload",
            bearer_token_id: "new-access",
            bearer_expires_at_epoch_secs: refresh_deadline,
        },
    )
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_root_expiry_rejects_while_refresh_is_unexpired() -> Result<(), String> {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|error| error.to_string())?;
    let mut conn = redis::Client::open(url)
        .and_then(|client| client.get_connection())
        .map_err(|error| error.to_string())?;
    for expired_root in [false, true] {
        let prefix = format!("refresh-root-expiry:{{{}}}", uuid::Uuid::new_v4());
        let keys: [String; 21] = std::array::from_fn(|index| format!("{prefix}:{index}"));
        let (now, _): (u64, u64) = redis::cmd("TIME")
            .query(&mut conn)
            .map_err(|error| error.to_string())?;
        let refresh_deadline = now + 3600;
        let root_deadline = if expired_root { now - 1 } else { now + 7200 };
        let previous = serde_json::json!({
            "rotated": false,
            "expires_at": {"secs_since_epoch": refresh_deadline},
        })
        .to_string();
        redis::cmd("SET")
            .arg(&keys[1])
            .arg(&previous)
            .query::<()>(&mut conn)
            .map_err(|error| error.to_string())?;
        let result = commit(
            &mut conn,
            &keys,
            &previous,
            now,
            refresh_deadline,
            root_deadline,
        )
        .map_err(|error| error.to_string())?;
        let (after, _): (u64, u64) = redis::cmd("TIME")
            .query(&mut conn)
            .map_err(|error| error.to_string())?;
        assert!(
            after < refresh_deadline,
            "ordinary refresh expiry is excluded"
        );
        if expired_root {
            assert_eq!(result, "invalid", "the root alone must deny publication");
            let retained: String = redis::cmd("GET")
                .arg(&keys[1])
                .query(&mut conn)
                .map_err(|error| error.to_string())?;
            assert_eq!(retained, previous, "rejection must not rotate the parent");
            let absent: Vec<&String> = keys
                .iter()
                .enumerate()
                .filter_map(|(index, key)| (index != 1).then_some(key))
                .collect();
            let count: usize = redis::cmd("EXISTS")
                .arg(&absent)
                .query(&mut conn)
                .map_err(|error| error.to_string())?;
            assert_eq!(count, 0, "rejection must not publish or change any index");
        } else {
            assert_eq!(result, "ok", "live root and refresh must commit");
            let count: usize = redis::cmd("EXISTS")
                .arg(&[&keys[8], &keys[13], &keys[16]])
                .query(&mut conn)
                .map_err(|error| error.to_string())?;
            assert_eq!(count, 3, "control must publish the complete grant");
        }
        redis::cmd("DEL")
            .arg(&keys)
            .query::<usize>(&mut conn)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_refresh_root_fractional_comparator_boundaries() {
    // Exercise the exact production guard at deterministic Redis-resolution
    // timestamps. The real-store test separately checks TIME and Rust transport.
    let source = super::COMMIT_REFRESH_ROTATION;
    let start = source
        .find("local current_time = redis_commit_time()")
        .unwrap();
    let end = source
        .find("local function system_time_epoch_secs")
        .unwrap();
    let body = format!(
        "local function redis_commit_time() return {{ARGV[1], ARGV[2]}} end\n{}\nreturn 'ok'",
        &source[start..end]
    );
    let script = super::super::super::refresh_grants::GrantCommit::script(&body);
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").unwrap();
    let mut conn = redis::Client::open(url).unwrap().get_connection().unwrap();
    let prefix = format!("root-comparator:{{{}}}", uuid::Uuid::new_v4());
    let keys: [String; 21] = std::array::from_fn(|i| format!("{prefix}:{i}"));
    for (seconds, micros, deadline_seconds, nanos, has_root, revoked, expected) in [
        (100_u64, 0_u32, 101_u64, 0_u32, true, false, "ok"),
        (100, 0, 100, 0, true, false, "invalid"),
        (100, 1, 100, 0, true, false, "invalid"),
        (100, 0, 100, 1, true, false, "ok"),
        (100, 949_999, 100, 950_000_000, true, false, "ok"),
        (100, 950_000, 100, 950_000_000, true, false, "invalid"),
        (100, 950_001, 100, 950_000_000, true, false, "invalid"),
        (100, 950_000, 100, 950_000_001, true, false, "ok"),
        (101, 0, 100, 999_999_999, true, false, "invalid"),
        (100, 0, u64::MAX, 999_999_999, true, false, "ok"),
        (100, 0, 101, 0, true, true, "invalid"),
        (100, 950_000, 100, 0, false, true, "ok"),
    ] {
        redis::cmd("DEL")
            .arg(&keys)
            .query::<usize>(&mut conn)
            .unwrap();
        if revoked {
            redis::cmd("SET")
                .arg(&keys[20])
                .arg("revoked")
                .query::<()>(&mut conn)
                .unwrap();
        }
        let mut invocation = script.prepare_invoke();
        invocation.key(&keys);
        let mut args = vec![String::new(); 20];
        args[0] = seconds.to_string();
        args[1] = micros.to_string();
        args[17] = if has_root { "1" } else { "0" }.into();
        args[18] = deadline_seconds.to_string();
        args[19] = nanos.to_string();
        invocation.arg(&args);
        super::super::super::refresh_grants::GrantCommit::independent_for_test(&keys[19])
            .append(&mut invocation);
        let actual: String = invocation.invoke(&mut conn).unwrap();
        assert_eq!(actual, expected, "now=({seconds},{micros}) deadline=({deadline_seconds},{nanos}) root={has_root} revoked={revoked}");
    }
    redis::cmd("DEL")
        .arg(&keys)
        .query::<usize>(&mut conn)
        .unwrap();
}
