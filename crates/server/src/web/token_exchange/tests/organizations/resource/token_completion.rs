use super::*;
use crate::organizations::request_work::{Admission, MAX_REQUESTS};
use std::io::Write;
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires isolated PostgreSQL and Redis; permanently closed admission child"]
fn shared_redis_organizations_token_read_lost_ack_closes_actual_http_admission() -> TestResult {
    let name = concat!(
        module_path!(),
        "::shared_redis_organizations_token_read_lost_ack_closes_actual_http_admission"
    )
    .split_once("::")
    .ok_or("missing crate prefix")?
    .1;
    replay_completion::run_child(name, exercise)
}

async fn exercise() -> TestResult {
    let fixture = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&fixture).await?;
    let result = exercise_request(&fixture, &state).await;
    state.db_pool.close().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while Admission::available_for_test() != MAX_REQUESTS {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    fixture.cleanup(result).await
}

async fn exercise_request(fixture: &Fixture, state: &AppState) -> TestResult {
    let key = aegaeon_crypto::signing::Ed25519SigningKey::generate()?;
    let (_, token) = issue(fixture, state, &key, PRIVILEGE).await?;
    let auth = format!("DPoP {token}");
    let signed = proof(state, &key, &token, "GET", json!({}))?;
    assert_eq!(
        get(state, Method::GET, PATH, Some(&auth), Some(&signed), "")
            .await?
            .0,
        StatusCode::OK
    );
    Admission::drain_for_test().await?;

    let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("redis://{}/", listener.local_addr()?);
    let expected = token.clone();
    let peer = std::thread::spawn(move || proxy(listener, &client, &expected));
    let mut failed = state.clone();
    let store = state.tokens.store.with_redis_transport_for_tests(&url)?;
    failed.tokens.validator = Arc::new(
        crate::authcode::TokenValidator::with_policy(
            store,
            state.keys.access_token.clone(),
            state.cfg.security_policy,
        )
        .with_issuer(Some(state.issuer.to_string()))
        .with_jwt_access_tokens_enabled(true),
    );
    failed.validate_subject_namespace().await?;
    assert!(
        failed.require_subject_namespace().is_ok(),
        "reach actual token-store fault"
    );
    let signed = proof(&failed, &key, &token, "GET", json!({}))?;
    let failed_response = get(&failed, Method::GET, PATH, Some(&auth), Some(&signed), "").await;
    let observed = tokio::task::spawn_blocking(move || {
        peer.join()
            .map_err(|_| anyhow::anyhow!("token proxy panicked"))?
    })
    .await??;
    let signed = proof(state, &key, &token, "GET", json!({}))?;
    let healthy_response = get(state, Method::GET, PATH, Some(&auth), Some(&signed), "").await?;
    assert!(observed, "actual selected token read before reply loss");
    assert_eq!(failed_response?.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        healthy_response.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "lost token read acknowledgement must keep actual HTTP admission closed"
    );
    Ok(())
}

fn proxy(
    listener: std::net::TcpListener,
    upstream: &redis::Client,
    expected: &str,
) -> anyhow::Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                anyhow::ensure!(Instant::now() < deadline, "proxy accept deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    };
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut actual = upstream.get_connection_with_timeout(Duration::from_secs(3))?;
    actual.set_read_timeout(Some(Duration::from_secs(3)))?;
    actual.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut parser = redis::Parser::new();
    let mut observed = false;
    for _ in 0..64 {
        let arguments = match parser.parse_value(&mut socket) {
            Ok(redis::Value::Array(arguments)) => arguments,
            Ok(_) => anyhow::bail!("proxy expected command array"),
            Err(error) => {
                anyhow::ensure!(
                    error.is_connection_dropped(),
                    "driver did not close: {error}"
                );
                return Ok(observed);
            }
        };
        let Some(redis::Value::BulkString(command)) = arguments.first() else {
            anyhow::bail!("proxy expected command");
        };
        if observed {
            continue;
        }
        match command.as_slice() {
            b"CLIENT" => socket.write_all(b"+OK\r\n")?,
            b"PING" => socket.write_all(b"+PONG\r\n")?,
            b"GET" => {
                anyhow::ensure!(arguments.len() == 2, "GET arity");
                let key: String = redis::from_redis_value(&arguments[1])?;
                let value: Option<Vec<u8>> = redis::cmd("GET").arg(key).query(&mut actual)?;
                if let Some(value) = value {
                    let record: Value = serde_json::from_slice(&value)?;
                    anyhow::ensure!(record["token"] == expected, "wrong actual token record");
                    observed = true;
                    // The actual access record was returned by Redis; lose the
                    // caller's acknowledgement and every subsequent response.
                } else {
                    socket.write_all(b"$-1\r\n")?;
                }
            }
            _ => anyhow::bail!("unexpected token read command"),
        }
    }
    anyhow::bail!("proxy command budget exceeded")
}
