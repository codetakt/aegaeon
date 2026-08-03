use std::sync::Arc;

use super::redis_backend::RedisAuthSessionBackend;
use super::redis_state::{RedisAuthSession, RedisAuthSessionKeyspace};
use super::{
    now_epoch_secs, AuthSession, AuthSessionBackend, AuthSessionStore, AuthSessionTimes,
    UpstreamLogoutSession,
};
use crate::config::DEFAULT_AUTH_SESSION_TTL_SECS;
use crate::upstream::{UpstreamClaimReleasePolicy, UpstreamLogoutRecoveryPolicy};

type WebAuthSessionTestResult = Result<(), String>;

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

fn redis_auth_session_store_for_test(url: &str, key: &str) -> Result<AuthSessionStore, String> {
    Ok(AuthSessionStore {
        backend: AuthSessionBackend::Redis(must_ok!(
            RedisAuthSessionBackend::new_with_prefix(url, Arc::<str>::from(key.to_string())),
            "redis auth session store",
        )),
        ttl_secs: 60,
        max_sessions: 10,
    })
}

fn clear_redis_auth_session_store_for_test(url: &str, key: &str) -> WebAuthSessionTestResult {
    let client = must_ok!(redis::Client::open(url), "redis test client");
    let mut conn = must_ok!(client.get_connection(), "redis test connection");
    let keyspace = RedisAuthSessionKeyspace::from_test_prefix(Arc::<str>::from(key.to_string()));
    let keys = must_ok!(
        redis::cmd("KEYS")
            .arg(format!("{}:*", keyspace.prefix()))
            .query::<Vec<String>>(&mut conn),
        "scan redis auth session store",
    );
    if !keys.is_empty() {
        must_ok!(
            redis::cmd("DEL").arg(keys).query::<usize>(&mut conn),
            "clear redis auth session v2 store",
        );
    }
    Ok(())
}

fn upstream_logout_session() -> UpstreamLogoutSession {
    UpstreamLogoutSession {
        issuer: "https://upstream.example".to_string(),
        end_session_endpoint: Some("https://upstream.example/logout".to_string()),
        back_channel: false,
        session_hint_claim: Some("sid".to_string()),
        session_hint_value: Some("upstream-sid".to_string()),
        recovery_policy: UpstreamLogoutRecoveryPolicy::ForcePromptLogin,
        team_id: Some(uuid::Uuid::new_v4()),
        tenant_id: Some(uuid::Uuid::new_v4()),
        environment_id: Some(uuid::Uuid::new_v4()),
        connection_id: Some(uuid::Uuid::new_v4()),
    }
}

#[test]
fn redis_auth_session_dto_round_trips_upstream_logout() -> WebAuthSessionTestResult {
    let logout = upstream_logout_session();
    let session = AuthSession {
        user_id: "user-A".to_string(),
        created_at_epoch_secs: 1_000,
        auth_time_epoch_secs: 900,
        expires_at_epoch_secs: 2_000,
        acr: Some("urn:example:acr".to_string()),
        claim_release_policy: Some(UpstreamClaimReleasePolicy {
            managed_custom_claims: vec!["department".to_string()],
            id_token_custom_claims: vec!["department".to_string()],
            userinfo_custom_claims: vec!["department".to_string()],
        }),
        upstream_logout: Some(logout.clone()),
    };

    let restored = must_some!(
        RedisAuthSession::from_session(&session).to_session(),
        "redis auth session DTO should decode",
    );

    assert_eq!(restored, session);
    assert_eq!(restored.upstream_logout, Some(logout));
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_auth_session_store_shares_user_lists_and_deletes() -> WebAuthSessionTestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "auth-session-test:v2:{{{}}}",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_auth_session_store_for_test(url.trim(), &key)?;

    let store_a = redis_auth_session_store_for_test(url.trim(), &key)?;
    let store_b = redis_auth_session_store_for_test(url.trim(), &key)?;
    let now = must_ok!(now_epoch_secs(), "test clock should be valid");
    let logout = upstream_logout_session();
    let sid_a = must_some!(
        store_a.create(
            "user-A",
            AuthSessionTimes::local(now),
            Some("urn:example:acr".to_string()),
            None,
            Some(logout.clone()),
        ),
        "session A should be created",
    );
    let sid_b = must_some!(
        store_b.create(
            "user-A",
            AuthSessionTimes::local(now.saturating_add(1)),
            None,
            None,
            None,
        ),
        "session B should be created",
    );

    assert_eq!(
        must_ok!(
            store_b.try_get(&sid_a),
            "redis auth session store should confirm lookup",
        )
        .and_then(|s| s.upstream_logout),
        Some(logout)
    );
    assert_eq!(
        must_ok!(
            store_a.try_list_for_user("user-A"),
            "redis auth session store should confirm list",
        )
        .len(),
        2
    );
    assert!(must_ok!(
        store_b.try_delete_for_user_session("user-A", &sid_a),
        "redis auth session store should confirm delete",
    ));
    assert!(must_ok!(
        store_a.try_get(&sid_a),
        "redis auth session store should confirm lookup",
    )
    .is_none());
    assert_eq!(
        must_ok!(
            store_a.try_delete_for_user("user-A"),
            "redis auth session store should confirm delete",
        ),
        1
    );
    assert!(must_ok!(
        store_b.try_get(&sid_b),
        "redis auth session store should confirm lookup",
    )
    .is_none());
    Ok(())
}

#[test]
fn try_delete_for_user_reports_successful_noop() -> WebAuthSessionTestResult {
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(
        DEFAULT_AUTH_SESSION_TTL_SECS,
        10,
    );

    let count = must_ok!(
        store.try_delete_for_user("user-UNKNOWN"),
        "in-memory auth session store should confirm no-op delete",
    );

    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn try_get_reports_successful_missing_session() -> WebAuthSessionTestResult {
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(
        DEFAULT_AUTH_SESSION_TTL_SECS,
        10,
    );

    let session = must_ok!(
        store.try_get("sid-UNKNOWN"),
        "in-memory auth session store should confirm missing lookup",
    );

    assert!(session.is_none());
    Ok(())
}

#[test]
fn try_list_for_user_reports_successful_empty_list() -> WebAuthSessionTestResult {
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(
        DEFAULT_AUTH_SESSION_TTL_SECS,
        10,
    );

    let sessions = must_ok!(
        store.try_list_for_user("user-UNKNOWN"),
        "in-memory auth session store should confirm empty list",
    );

    assert!(sessions.is_empty());
    Ok(())
}

#[test]
fn try_delete_for_user_session_reports_successful_not_found() -> WebAuthSessionTestResult {
    let store = AuthSessionStore::new_process_local_with_limits_for_tests(
        DEFAULT_AUTH_SESSION_TTL_SECS,
        10,
    );

    let deleted = must_ok!(
        store.try_delete_for_user_session("user-UNKNOWN", "sid-UNKNOWN"),
        "in-memory auth session store should confirm not-found delete",
    );

    assert!(!deleted);
    Ok(())
}
