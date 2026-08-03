use super::keyspace::RedisStepUpKeyspace;
use super::*;
use std::sync::Arc;

type StepUpTestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_ok {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(value) => value,
            Err(err) => fail_test!("{}: {:?}", $context, err),
        }
    };
}

macro_rules! must_some {
    ($value:expr, $context:expr $(,)?) => {
        match $value {
            Some(value) => value,
            None => fail_test!("{}", $context),
        }
    };
}

#[test]
fn issue_and_consume_is_single_use() -> StepUpTestResult {
    let store = StepUpStore::new_process_local_with_ttl_for_tests(Duration::from_secs(30));
    let now = 100;
    let challenge = must_some!(
        store.issue_challenge("client", "session", "request", now),
        "challenge issued",
    );
    assert_eq!(challenge.client_id, "client");
    assert_eq!(challenge.session_id, "session");
    assert_eq!(challenge.request_id, "request");
    assert_eq!(challenge.issued_at_epoch_secs, now);
    assert_eq!(challenge.expires_at_epoch_secs, now + 30);

    assert!(store
        .complete_for_request("client", "session", "request", now + 1)
        .is_some());
    assert!(store.consume_completed("client", "session", "request", now + 1));
    assert!(!store.consume_completed("client", "session", "request", now + 1));
    Ok(())
}

fn redis_stepup_store_for_test(url: &str, key: &str) -> Result<StepUpStore, String> {
    Ok(StepUpStore {
        backend: StepUpStoreBackend::Redis(must_ok!(
            RedisStepUpStoreBackend::new_with_prefix(url, Arc::<str>::from(key.to_string())),
            "redis step-up store",
        )),
        ttl: Duration::from_secs(30),
    })
}

fn clear_redis_stepup_store_for_test(url: &str, key: &str) -> StepUpTestResult {
    let client = must_ok!(redis::Client::open(url), "redis test client");
    let mut conn = must_ok!(client.get_connection(), "redis test connection");
    let keyspace = RedisStepUpKeyspace::from_test_prefix(Arc::<str>::from(key.to_string()));
    let keys = must_ok!(
        redis::cmd("KEYS")
            .arg(format!("{}:*", keyspace.prefix))
            .query::<Vec<String>>(&mut conn),
        "scan redis step-up store",
    );
    if !keys.is_empty() {
        must_ok!(
            redis::cmd("DEL").arg(keys).query::<usize>(&mut conn),
            "clear redis step-up v2 store",
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_stepup_store_shares_completion_and_single_use() -> StepUpTestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "stepup-test:v2:{{{}}}",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_stepup_store_for_test(url.trim(), &key)?;
    let store_a = redis_stepup_store_for_test(url.trim(), &key)?;
    let store_b = redis_stepup_store_for_test(url.trim(), &key)?;
    let now = 100;

    let challenge = must_some!(
        store_a.issue_challenge("client", "session", "request", now),
        "challenge issued",
    );
    assert_eq!(challenge.client_id, "client");
    assert!(store_b
        .complete_for_request("client", "session", "request", now + 1)
        .is_some());
    assert!(store_a.consume_completed("client", "session", "request", now + 1));
    assert!(!store_b.consume_completed("client", "session", "request", now + 1));
    Ok(())
}

#[test]
fn issue_challenge_clamps_ttl() -> StepUpTestResult {
    let store = StepUpStore::new_process_local_with_ttl_for_tests(Duration::from_secs(u64::MAX));
    let now = 100;
    let challenge = must_some!(
        store.issue_challenge("client", "session", "request", now),
        "challenge issued",
    );

    assert_eq!(
        challenge.expires_at_epoch_secs,
        now + MAX_STEPUP_CHALLENGE_TTL_SECS
    );
    Ok(())
}

#[test]
fn issue_challenge_overflow_fails_without_state_mutation() {
    let store = StepUpStore::new_process_local_with_ttl_for_tests(Duration::from_secs(30));
    let now = u64::MAX;

    assert!(store
        .issue_challenge("client", "session", "request", now)
        .is_none());
    assert!(store
        .complete_for_request("client", "session", "request", now)
        .is_none());
}

#[test]
fn expired_challenges_are_rejected() {
    let store = StepUpStore::new_process_local_with_ttl_for_tests(Duration::from_secs(1));
    let now = 200;
    let _ = store.issue_challenge("client", "session", "request", now);
    assert!(store
        .complete_for_request("client", "session", "request", now + 2)
        .is_none());
    assert!(!store.consume_completed("client", "session", "request", now + 2));
    store.cleanup_expired();
    assert!(store
        .complete_for_request("client", "session", "request", now + 3)
        .is_none());
}
