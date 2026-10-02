//! Raw script failure-prefix tests; Rust record validation is exercised separately.
use super::*;

#[test]
#[ignore = "requires private Redis"]
fn redis_exchange_commit_distinguishes_subject_changes_from_unrelated_versions(
) -> Result<(), String> {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    let mut conn = redis::Client::open(url)
        .and_then(|client| client.get_connection())
        .map_err(|e| e.to_string())?;
    for case in [
        "control",
        "subject",
        "revoked",
        "version",
        "index",
        "lease",
        "expired",
        "fractional_expired",
    ] {
        let prefix = format!("exchange-prefix-{}", uuid::Uuid::new_v4());
        let keys: Vec<_> = (1..=15).map(|i| format!("{prefix}:{i}")).collect();
        for (index, value) in [
            (0, "lease"),
            (1, "2"),
            (2, "parent"),
            (3, "meta"),
            (4, "subject"),
        ] {
            redis::cmd("SET")
                .arg(&keys[index])
                .arg(value)
                .query::<()>(&mut conn)
                .map_err(|e| e.to_string())?;
        }
        match case {
            "subject" => {
                redis::cmd("SET")
                    .arg(&keys[3])
                    .arg("changed")
                    .query::<()>(&mut conn)
                    .map_err(|e| e.to_string())?;
            }
            "revoked" => {
                redis::cmd("SET")
                    .arg(&keys[6])
                    .arg("denied")
                    .query::<()>(&mut conn)
                    .map_err(|e| e.to_string())?;
            }
            "index" => {
                redis::cmd("SET")
                    .arg(&keys[10])
                    .arg("wrong-type")
                    .query::<()>(&mut conn)
                    .map_err(|e| e.to_string())?;
            }
            "lease" => {
                redis::cmd("SET")
                    .arg(&keys[0])
                    .arg("new-owner")
                    .query::<()>(&mut conn)
                    .map_err(|e| e.to_string())?;
            }
            _ => {}
        }
        let version = if matches!(case, "subject" | "revoked" | "version") {
            "1"
        } else {
            "2"
        };
        let expiry = if case == "expired" { "1" } else { "4102444800" };
        let script_body = if case == "fractional_expired" {
            // Synthetic input, based on real Redis TIME within this invocation.
            // The before/after check proves COMMIT actually used the same second;
            // if the second changes, retry the no-write expired-root operation.
            format!("local before = redis.call('TIME')\nARGV[13] = before[1]\nARGV[18] = tostring(tonumber(before[2]) * 1000)\nlocal function execute_exchange()\n{COMMIT}\nend\nlocal outcome = execute_exchange()\nif redis.call('TIME')[1] ~= before[1] then return 'boundary_second_changed' end\nreturn outcome")
        } else {
            COMMIT.to_string()
        };
        let script = super::super::refresh_grants::GrantCommit::script(&script_body);
        let mut invocation = script.prepare_invoke();
        invocation.key(&keys).arg(&[
            "lease",
            version,
            "parent",
            "meta",
            "subject",
            expiry,
            expiry,
            expiry,
            "output",
            "output-meta",
            "children",
            "id",
            expiry,
            "1",
            "0", // parent nanoseconds, ARGV15
            "0", // subject nanoseconds, ARGV16
            "0", // output nanoseconds, ARGV17
            "0", // exchange-root nanoseconds, ARGV18
        ]);
        super::super::refresh_grants::GrantCommit::independent_for_test(&keys[1])
            .append(&mut invocation);
        let mut result = String::new();
        for _ in 0..3 {
            result = invocation.invoke(&mut conn).map_err(|e| e.to_string())?;
            if result != "boundary_second_changed" {
                break;
            }
        }
        let expected = match case {
            "control" => "ok",
            "subject" => "stale_subject",
            "revoked" => "revoked",
            "version" => "stale_version",
            "index" => "index_type",
            "lease" => "lost_lock",
            _ => "expired_root",
        };
        assert_eq!(
            result, expected,
            "case {case} must complete with its asserted time boundary"
        );
        let result = interpret_commit_result(result);
        if case == "control" {
            result?;
        } else {
            let error = result.expect_err("failure must reject publication");
            if matches!(
                case,
                "subject" | "revoked" | "expired" | "fractional_expired"
            ) {
                assert!(matches!(error, ExchangeCommitError::Rejected(_)));
            } else {
                assert!(matches!(error, ExchangeCommitError::Storage(_)));
            }
            let count: u32 = redis::cmd("EXISTS")
                .arg(&keys[7..9])
                .query(&mut conn)
                .map_err(|e| e.to_string())?;
            assert_eq!(count, 0, "no output after {case}");
        }
        redis::cmd("DEL")
            .arg(&keys)
            .query::<()>(&mut conn)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
