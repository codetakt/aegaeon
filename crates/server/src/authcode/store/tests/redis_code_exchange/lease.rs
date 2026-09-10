//! Real lease expiry/retry characterization of the production Redis adapter.
use super::*;
use std::time::{Duration, Instant};

fn lock_key(issuer: &TokenIssuer, code: &str) -> Result<String, String> {
    let context = issuer
        .code_store
        .redis_commit_context(code)
        .ok_or_else(|| "Redis context missing".to_string())?;
    let key = context.code_key.replace(":code:", ":exchange-lock:");
    assert_ne!(key, context.code_key);
    Ok(key)
}

fn connect(url: &str) -> Result<redis::Connection, String> {
    redis::Client::open(url)
        .and_then(|client| client.get_connection())
        .map_err(|error| error.to_string())
}

fn owner(conn: &mut redis::Connection, key: &str) -> Result<Option<String>, String> {
    redis::cmd("GET")
        .arg(key)
        .query(conn)
        .map_err(|error| error.to_string())
}

fn expire(conn: &mut redis::Connection, key: &str) -> Result<(), String> {
    let ttl: i64 = redis::cmd("PTTL")
        .arg(key)
        .query(conn)
        .map_err(|e| e.to_string())?;
    assert!(ttl > 0 && ttl <= 30_000);
    redis::cmd("PEXPIRE")
        .arg(key)
        .arg(1)
        .query::<bool>(conn)
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    while owner(conn, key)?.is_some() {
        assert!(start.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
async fn redis_code_exchange_expired_owner_cannot_release_successor() -> StoreTestResult {
    let url = redis_url()?;
    for asynchronous in [false, true] {
        let (issuer, code) = issuer_with_code(&url)?;
        let key = lock_key(&issuer, &code)?;
        let mut conn = connect(&url)?;
        let stale = issuer.code_store.acquire_exchange_lock(&code)?;
        let stale_owner = owner(&mut conn, &key)?;
        assert!(stale_owner.is_some());
        expire(&mut conn, &key)?;
        let successor = issuer
            .code_store
            .acquire_exchange_lock_async(code.clone())
            .await?;
        let successor_owner = owner(&mut conn, &key)?;
        assert!(successor_owner.is_some());
        assert_ne!(stale_owner, successor_owner);
        if asynchronous {
            stale.release_async().await;
        } else {
            stale.release();
        }
        assert_eq!(owner(&mut conn, &key)?, successor_owner);
        successor.release_async().await;
        assert_eq!(owner(&mut conn, &key)?, None);
        assert!(matches!(
            issuer.exchange_code_for_tokens(request(&code), None)?,
            TokenResponse::Success { .. }
        ));
        assert!(invalid_code(
            issuer.exchange_code_for_tokens(request(&code), None)
        ));
    }
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_lease_timeout_does_not_consume_or_publish() -> StoreTestResult {
    let url = redis_url()?;
    let (issuer, code) = issuer_with_code(&url)?;
    let key = lock_key(&issuer, &code)?;
    let mut conn = connect(&url)?;
    let held = issuer.code_store.acquire_exchange_lock(&code)?;
    let held_owner = owner(&mut conn, &key)?;
    let snapshot = issuer.code_store.try_get_code(&code)?;
    let start = Instant::now();
    let result = issuer.exchange_code_for_tokens(request(&code), None);
    assert!(
        matches!(result, Ok(TokenResponse::Error { ref error, error_description: Some(ref description) }) if error == "server_error" && description.contains("timed out")),
        "{result:?}"
    );
    assert!(start.elapsed() >= Duration::from_secs(2));
    assert!(issuer.code_store.try_get_code(&code)?.is_some());
    assert_eq!(
        serde_json::to_value(snapshot).map_err(|error| error.to_string())?,
        serde_json::to_value(issuer.code_store.try_get_code(&code)?)
            .map_err(|error| error.to_string())?
    );
    assert_eq!(owner(&mut conn, &key)?, held_owner);
    held.release();
    assert!(matches!(
        issuer.exchange_code_for_tokens(request(&code), None)?,
        TokenResponse::Success { .. }
    ));
    assert!(invalid_code(
        issuer.exchange_code_for_tokens(request(&code), None)
    ));
    Ok(())
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_code_exchange_drop_releases_owned_lease() -> StoreTestResult {
    let url = redis_url()?;
    let (issuer, code) = issuer_with_code(&url)?;
    let key = lock_key(&issuer, &code)?;
    let mut conn = connect(&url)?;
    let held = issuer.code_store.acquire_exchange_lock(&code)?;
    assert!(owner(&mut conn, &key)?.is_some());
    drop(held);
    let start = Instant::now();
    while owner(&mut conn, &key)?.is_some() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        issuer.exchange_code_for_tokens(request(&code), None)?,
        TokenResponse::Success { .. }
    ));
    Ok(())
}
