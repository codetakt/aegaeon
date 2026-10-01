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
            exchange_root_deadline: root_deadline,
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
