use super::{OidcSessionContext, OidcSessionStore};
use std::fmt::Display;

type TestResult = Result<(), String>;

fn test_context<T, E: Display>(result: Result<T, E>, context: &str) -> Result<T, String> {
    result.map_err(|err| format!("{context}: {err}"))
}

fn test_err<T, E>(result: Result<T, E>, context: &str) -> Result<E, String> {
    result.err().ok_or_else(|| context.to_string())
}

fn session_context<'a>(user_id: &'a str, auth_session_id: &'a str) -> OidcSessionContext<'a> {
    OidcSessionContext {
        user_id,
        auth_session_id,
    }
}

fn clear_redis_oidc_session_store_for_test(url: &str, key: &str) -> TestResult {
    let client = test_context(redis::Client::open(url), "redis test client")?;
    let mut conn = test_context(client.get_connection(), "redis test connection")?;
    let keys = redis::cmd("KEYS")
        .arg(format!("{key}:*"))
        .query::<Vec<String>>(&mut conn)
        .map_err(|err| format!("scan redis OIDC session store: {err}"))?;
    if !keys.is_empty() {
        redis::cmd("DEL")
            .arg(keys)
            .query::<usize>(&mut conn)
            .map_err(|err| format!("clear redis OIDC session v3 store: {err}"))?;
    }
    Ok(())
}

fn redis_string_key_pointing_to_sid_for_test(
    url: &str,
    key: &str,
    key_kind: &str,
    sid: &str,
) -> Result<String, String> {
    let client = test_context(redis::Client::open(url), "redis test client")?;
    let mut conn = test_context(client.get_connection(), "redis test connection")?;
    let keys = redis::cmd("KEYS")
        .arg(format!("{key}:{key_kind}:*"))
        .query::<Vec<String>>(&mut conn)
        .map_err(|err| format!("scan redis OIDC {key_kind} keys: {err}"))?;

    for redis_key in keys {
        let value = redis::cmd("GET")
            .arg(&redis_key)
            .query::<Option<String>>(&mut conn)
            .map_err(|err| format!("read redis OIDC {key_kind} key: {err}"))?;
        if value.as_deref() == Some(sid) {
            return Ok(redis_key);
        }
    }
    Err(format!("redis OIDC {key_kind} key for sid {sid} not found"))
}

fn redis_set_string_for_test(url: &str, key: &str, value: &str) -> TestResult {
    let client = test_context(redis::Client::open(url), "redis test client")?;
    let mut conn = test_context(client.get_connection(), "redis test connection")?;
    redis::cmd("SET")
        .arg(key)
        .arg(value)
        .query::<()>(&mut conn)
        .map_err(|err| format!("set redis string key {key}: {err}"))
}

#[test]
fn try_get_or_create_session_returns_non_empty_sid() -> TestResult {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);
    let sid = store
        .try_get_or_create_session(session_context("user", "auth-session-a"))
        .map_err(|err| format!("session allocation should succeed: {err}"))?;

    assert!(!sid.is_empty());
    Ok(())
}

#[test]
fn try_add_client_rejects_unknown_or_logged_out_session() -> TestResult {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);
    let sid = store
        .try_get_or_create_session(session_context("user", "auth-session-a"))
        .map_err(|err| format!("session allocation should succeed: {err}"))?;

    assert!(!store
        .try_add_client("missing", "client")
        .map_err(|err| format!("in-memory add-client lookup should be confirmed: {err}"))?);
    assert!(store
        .try_add_client(&sid, "client")
        .map_err(|err| format!("in-memory add-client mutation should be confirmed: {err}"))?);
    assert!(store.logout_by_sid_at(&sid, 100).is_some());
    assert!(!store
        .try_add_client(&sid, "other-client")
        .map_err(|err| format!("in-memory add-client lookup should be confirmed: {err}"))?);
    Ok(())
}

#[test]
fn try_logout_by_sid_reports_missing_session_without_backend_error() -> TestResult {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);

    let event = store
        .try_logout_by_sid("missing")
        .map_err(|err| format!("in-memory logout lookup should be confirmed: {err}"))?;

    assert!(event.is_none());
    Ok(())
}

#[test]
fn try_logout_by_user_reports_backend_unavailable() -> TestResult {
    let store = OidcSessionStore::new_redis_for_test("redis://127.0.0.1:1/", "unavailable", 10)?;

    let err = test_err(
        store.try_logout_by_user("user"),
        "unavailable Redis session store must be reported",
    )?;

    assert!(err.contains("OIDC session store backend unavailable"));
    Ok(())
}

#[test]
fn logged_out_session_expires_at_ttl_boundary() {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);
    let sid = store.get_or_create_session("user", "auth-session-a");
    assert!(store.logout_by_sid_at(&sid, 100).is_some());

    store.prune_expired_at(110);

    assert!(store.logout_by_sid_at(&sid, 111).is_none());
    assert_ne!(sid, store.get_or_create_session("user", "auth-session-a"));
}

#[test]
fn future_logout_timestamp_is_pruned_fail_closed() {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);
    let sid = store.get_or_create_session("user", "auth-session-a");
    assert!(store.logout_by_sid_at(&sid, 100).is_some());

    store.prune_expired_at(99);

    assert!(store.logout_by_sid_at(&sid, 100).is_none());
    assert_ne!(sid, store.get_or_create_session("user", "auth-session-a"));
}

#[test]
fn explicit_ttl_is_clamped_to_maximum() {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(u64::MAX);
    let sid = store.get_or_create_session("user", "auth-session-a");
    assert!(store.logout_by_sid_at(&sid, 0).is_some());

    store.prune_expired_at(86_400);

    assert!(store.logout_by_sid_at(&sid, 86_401).is_none());
    assert_ne!(sid, store.get_or_create_session("user", "auth-session-a"));
}

#[test]
fn same_user_distinct_auth_sessions_receive_distinct_oidc_sids() {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);

    let sid_a = store.get_or_create_session("user", "auth-session-a");
    let sid_b = store.get_or_create_session("user", "auth-session-b");
    let sid_a_again = store.get_or_create_session("user", "auth-session-a");

    assert_ne!(sid_a, sid_b);
    assert_eq!(sid_a, sid_a_again);
}

#[test]
fn logout_by_user_reports_all_auth_session_scoped_events() {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);
    let sid_a = store.get_or_create_session("user", "auth-session-a");
    let sid_b = store.get_or_create_session("user", "auth-session-b");
    store.add_client(&sid_a, "client-a");
    store.add_client(&sid_b, "client-b");

    let events = store.logout_by_user("user");

    assert_eq!(events.len(), 2);
    let event_a = events
        .iter()
        .find(|event| event.sid == sid_a)
        .expect("auth-session-a logout event should be present");
    let event_b = events
        .iter()
        .find(|event| event.sid == sid_b)
        .expect("auth-session-b logout event should be present");
    assert_eq!(event_a.client_ids, vec!["client-a"]);
    assert_eq!(event_b.client_ids, vec!["client-b"]);
}

#[test]
fn logout_by_auth_session_id_only_logs_out_linked_session() -> TestResult {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);
    let sid_a = store.get_or_create_session("user", "auth-session-a");
    let sid_b = store.get_or_create_session("user", "auth-session-b");
    store.add_client(&sid_a, "client-a");
    store.add_client(&sid_b, "client-b");

    let event = store
        .try_logout_by_auth_session_id("auth-session-a")
        .map_err(|err| format!("in-memory logout by auth-session should succeed: {err}"))?
        .ok_or_else(|| "auth-session-a logout event should be present".to_string())?;

    assert_eq!(event.sid, sid_a);
    assert_eq!(event.client_ids, vec!["client-a"]);
    assert!(store
        .try_logout_by_auth_session_id("auth-session-a")
        .map_err(|err| format!("repeated auth-session logout should be confirmed: {err}"))?
        .is_none());
    assert_eq!(sid_b, store.get_or_create_session("user", "auth-session-b"));
    Ok(())
}

#[test]
fn logout_by_auth_session_id_reports_missing_session_without_backend_error() -> TestResult {
    let store = OidcSessionStore::new_process_local_with_ttl_for_tests(10);

    let event = store
        .try_logout_by_auth_session_id("missing-auth-session")
        .map_err(|err| {
            format!("in-memory auth-session logout lookup should be confirmed: {err}")
        })?;

    assert!(event.is_none());
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_oidc_session_store_shares_logout_jti_clients_and_pruning() -> TestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "oidc-logout-session-test:v3:{{{}}}",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_oidc_session_store_for_test(url.trim(), &key)?;

    let store_a = OidcSessionStore::new_redis_for_test(url.trim(), &key, 10)?;
    let store_b = OidcSessionStore::new_redis_for_test(url.trim(), &key, 10)?;
    let sid = store_a
        .try_get_or_create_session(session_context("user", "auth-session-a"))
        .map_err(|err| format!("session should be created: {err}"))?;

    assert_eq!(
        store_b
            .try_get_or_create_session(session_context("user", "auth-session-a"))
            .map_err(|err| format!("session should be read: {err}"))?,
        sid
    );
    let other_browser_sid = store_b
        .try_get_or_create_session(session_context("user", "auth-session-b"))
        .map_err(|err| format!("second auth session should be created: {err}"))?;
    assert_ne!(sid, other_browser_sid);
    assert!(store_b
        .try_add_client(&sid, "client-b")
        .map_err(|err| format!("redis add-client mutation should be confirmed: {err}"))?);
    assert!(store_a
        .try_add_client(&sid, "client-a")
        .map_err(|err| format!("redis add-client mutation should be confirmed: {err}"))?);

    let event = store_b
        .logout_by_sid_at(&sid, 100)
        .ok_or_else(|| "logout event should be emitted".to_string())?;
    assert_eq!(event.client_ids, vec!["client-a", "client-b"]);
    let repeated = store_a
        .logout_by_sid_at(&sid, 101)
        .ok_or_else(|| "logout event should be idempotent before TTL".to_string())?;
    assert_eq!(repeated.jti, event.jti);
    assert_ne!(sid, store_b.get_or_create_session("user", "auth-session-a"));
    assert_eq!(
        other_browser_sid,
        store_b.get_or_create_session("user", "auth-session-b")
    );

    store_a.prune_expired_at(110);
    assert!(store_b.logout_by_sid_at(&sid, 111).is_none());

    let future_sid = store_a.get_or_create_session("future-user", "future-auth-session");
    assert!(store_a.logout_by_sid_at(&future_sid, 100).is_some());
    store_b.prune_expired_at(99);
    assert!(store_a.logout_by_sid_at(&future_sid, 100).is_none());
    assert_ne!(
        future_sid,
        store_b.get_or_create_session("future-user", "future-auth-session")
    );
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_oidc_logout_by_auth_session_id_only_logs_out_linked_session() -> TestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "oidc-logout-session-test:v3:{{{}}}",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_oidc_session_store_for_test(url.trim(), &key)?;

    let store = OidcSessionStore::new_redis_for_test(url.trim(), &key, 10)?;
    let sid_a = store
        .try_get_or_create_session(session_context("user", "auth-session-a"))
        .map_err(|err| format!("first auth session should be created: {err}"))?;
    let sid_b = store
        .try_get_or_create_session(session_context("user", "auth-session-b"))
        .map_err(|err| format!("second auth session should be created: {err}"))?;
    assert!(store
        .try_add_client(&sid_a, "client-a")
        .map_err(|err| format!("redis add-client mutation should be confirmed: {err}"))?);
    assert!(store
        .try_add_client(&sid_b, "client-b")
        .map_err(|err| format!("redis add-client mutation should be confirmed: {err}"))?);

    let event = store
        .try_logout_by_auth_session_id("auth-session-a")
        .map_err(|err| format!("redis logout by auth-session should succeed: {err}"))?
        .ok_or_else(|| "auth-session-a logout event should be present".to_string())?;

    assert_eq!(event.sid, sid_a);
    assert_eq!(event.client_ids, vec!["client-a"]);
    assert!(store
        .try_logout_by_auth_session_id("auth-session-a")
        .map_err(|err| format!("repeated redis auth-session logout should be confirmed: {err}"))?
        .is_none());
    assert_eq!(sid_b, store.get_or_create_session("user", "auth-session-b"));
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_oidc_logout_by_user_reports_all_auth_session_scoped_events() -> TestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let key = format!(
        "oidc-logout-session-test:v3:{{{}}}",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_oidc_session_store_for_test(url.trim(), &key)?;

    let store = OidcSessionStore::new_redis_for_test(url.trim(), &key, 10)?;
    let sid_a = store
        .try_get_or_create_session(session_context("user", "auth-session-a"))
        .map_err(|err| format!("first auth session should be created: {err}"))?;
    let sid_b = store
        .try_get_or_create_session(session_context("user", "auth-session-b"))
        .map_err(|err| format!("second auth session should be created: {err}"))?;
    assert!(store
        .try_add_client(&sid_a, "client-a")
        .map_err(|err| format!("redis add-client mutation should be confirmed: {err}"))?);
    assert!(store
        .try_add_client(&sid_b, "client-b")
        .map_err(|err| format!("redis add-client mutation should be confirmed: {err}"))?);

    let events = store
        .try_logout_by_user("user")
        .map_err(|err| format!("redis logout-by-user should succeed: {err}"))?;

    assert_eq!(events.len(), 2);
    let event_a = events
        .iter()
        .find(|event| event.sid == sid_a)
        .ok_or_else(|| "auth-session-a logout event should be present".to_string())?;
    let event_b = events
        .iter()
        .find(|event| event.sid == sid_b)
        .ok_or_else(|| "auth-session-b logout event should be present".to_string())?;
    assert_eq!(event_a.client_ids, vec!["client-a"]);
    assert_eq!(event_b.client_ids, vec!["client-b"]);
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_oidc_stale_auth_session_alias_does_not_delete_target_session_clients() -> TestResult {
    let redis_url_env = ["AEGAEON", "TEST_REDIS_URL"].join("_");
    let Ok(url) = std::env::var(redis_url_env) else {
        return Ok(());
    };
    let url = url.trim();
    let key = format!(
        "oidc-logout-session-test:v3:{{{}}}",
        aegaeon_crypto::rand::random_base64url(8)
    );
    clear_redis_oidc_session_store_for_test(url, &key)?;

    let store = OidcSessionStore::new_redis_for_test(url, &key, 10)?;
    let sid_a = store
        .try_get_or_create_session(session_context("user", "auth-session-a"))
        .map_err(|err| format!("first auth session should be created: {err}"))?;
    let sid_b = store
        .try_get_or_create_session(session_context("user", "auth-session-b"))
        .map_err(|err| format!("second auth session should be created: {err}"))?;
    assert!(store
        .try_add_client(&sid_b, "client-b")
        .map_err(|err| format!("redis add-client mutation should be confirmed: {err}"))?);

    let auth_session_a_key =
        redis_string_key_pointing_to_sid_for_test(url, &key, "auth-session", &sid_a)?;
    redis_set_string_for_test(url, &auth_session_a_key, &sid_b)?;

    let replacement_sid = store
        .try_get_or_create_session(session_context("user", "auth-session-a"))
        .map_err(|err| format!("replacement auth session should be created: {err}"))?;

    assert_ne!(replacement_sid, sid_a);
    assert_ne!(replacement_sid, sid_b);
    let event = store
        .logout_by_sid_at(&sid_b, 100)
        .ok_or_else(|| "target session should still be logout-capable".to_string())?;
    assert_eq!(event.client_ids, vec!["client-b"]);
    Ok(())
}
