use super::*;

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn dpop_retention_redis_pttl_duplicate_and_backend_failure() -> TestResult {
    let url = std::env::var("AEGAEON_TEST_REDIS_URL").map_err(|e| e.to_string())?;
    let store = Arc::new(RedisReplayStore::new_for_tests(&url).map_err(|e| e.to_string())?);
    let namespace = format!("dpop-retention-{}", uuid::Uuid::new_v4());
    let middleware = DpopMiddleware::new(
        namespace.clone(),
        "https://issuer.example",
        store,
        Duration::from_secs(1),
    );
    let token = proof(1_700_000_300, None);
    let jkt = compute_dpop_jkt_from_proof_with_max_len(
        &token,
        aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
    )
    .ok_or("jkt")?;
    let material = DpopMiddleware::replay_material("retained-proof", &jkt);
    let key = ReplayEntry::new(&namespace, &material, Duration::ZERO).encoded_key();
    let mut connection = ::redis::Client::open(url)
        .map_err(|e| e.to_string())?
        .get_connection()
        .map_err(|e| e.to_string())?;
    let started = std::time::Instant::now();
    assert!(verify_at(&middleware, &token, 1_700_000_000_000).is_ok());
    let ttl: i64 = ::redis::cmd("PTTL")
        .arg(&key)
        .query(&mut connection)
        .map_err(|e| e.to_string())?;
    let elapsed = i64::try_from(started.elapsed().as_millis()).map_err(|e| e.to_string())?;
    assert!(
        elapsed <= 5000 && ttl > 0 && ttl <= 601_000 && ttl >= 601_000 - elapsed - 1000,
        "pttl={ttl}, elapsed={elapsed}"
    );
    assert_eq!(
        verify_at(&middleware, &token, 1_700_000_000_000),
        Err(DpopError::Replay)
    );
    let _: i64 = ::redis::cmd("DEL")
        .arg(&key)
        .query(&mut connection)
        .map_err(|e| e.to_string())?;
    // An owned endpoint accepts and closes without speaking Redis.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let server = std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });
    let unavailable = Arc::new(
        RedisReplayStore::new_for_tests(&format!("redis://{addr}/")).map_err(|e| e.to_string())?,
    );
    let middleware = DpopMiddleware::new(
        namespace,
        "https://issuer.example",
        unavailable,
        Duration::from_secs(1),
    );
    assert!(matches!(
        verify_at(&middleware, &token, 1_700_000_000_000),
        Err(DpopError::BackendUnavailable(_))
    ));
    server
        .join()
        .map_err(|_| "owned Redis failure endpoint panicked".to_string())?;
    Ok(())
}
