use super::*;
use crate::organizations::request_work::{Admission, MAX_REQUESTS};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires isolated PostgreSQL and Redis; permanently closed admission child"]
fn shared_redis_organizations_replay_lost_ack_closes_actual_http_admission() -> TestResult {
    let name = concat!(
        module_path!(),
        "::shared_redis_organizations_replay_lost_ack_closes_actual_http_admission"
    )
    .split_once("::")
    .ok_or("missing crate prefix")?
    .1;
    run_child(name, exercise)
}

pub(super) fn run_child<F: std::future::Future<Output = TestResult>>(
    name: &str,
    scenario: impl FnOnce() -> F,
) -> TestResult {
    const CHILD: &str = "AEGAEON_TEST_ORGANIZATION_REPLAY_CHILD";
    if let Some(marker) = std::env::var_os(CHILD) {
        assert_eq!(marker, name);
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(scenario());
    }
    // Closure is permanent for this process. Never reset the production gate
    // for a test or contaminate the other tests in the standard suite.
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            name,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
            "--format=pretty",
            "--color=never",
        ])
        .env(CHILD, name)
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or("child stdout")?;
    let output = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut retained = Vec::new();
        let mut bytes = [0; 8192];
        loop {
            let size = stdout.read(&mut bytes)?;
            if size == 0 {
                return Ok(retained);
            }
            retained.extend_from_slice(&bytes[..size]);
            if retained.len() > 65536 {
                retained.drain(..retained.len() - 65536);
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = output
        .join()
        .map_err(|_| "child output worker panicked")??;
    let output = String::from_utf8_lossy(&output);
    assert!(
        status.is_some_and(|status| status.success())
            && output.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
            && output.contains(&format!("test {name} ... ok")),
        "store child failed or missed its test: {status:?}\n{output}"
    );
    Ok(())
}

async fn exercise() -> TestResult {
    let fixture = Fixture::with_identifier(IDENTIFIER).await?;
    let state = setup(&fixture).await?;
    let result = exercise_request(&fixture, &state).await;
    state.db_pool.close().await;
    // The closed class cannot be reacquired, even after all workers terminate.
    // Observe ownership without reopening it or claiming restart recovery.
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
    let upstream = client.clone();
    let peer = std::thread::spawn(move || proxy(listener, &upstream));
    let mut failed = state.clone();
    failed.dpop = Arc::new(
        crate::middleware::DpopMiddleware::new(
            state.environment_id.to_string(),
            state.issuer.as_str(),
            Arc::new(crate::middleware::replay_store::RedisReplayStore::new_for_tests(&url)?),
            Duration::from_secs(360),
        )
        .with_native_verifier_for_tests(),
    );
    let signed = proof(&failed, &key, &token, "GET", json!({}))?;
    let failed_response = get(&failed, Method::GET, PATH, Some(&auth), Some(&signed), "").await;
    let (replay_key, mutations) = tokio::task::spawn_blocking(move || {
        peer.join()
            .map_err(|_| anyhow::anyhow!("replay proxy panicked"))?
    })
    .await??;
    let value = tokio::task::spawn_blocking(move || -> redis::RedisResult<Option<String>> {
        let mut connection = crate::redis_io::connect(&client)?;
        let value = redis::cmd("GET").arg(&replay_key).query(&mut connection)?;
        redis::cmd("DEL")
            .arg(&replay_key)
            .query::<i64>(&mut connection)?;
        Ok(value)
    })
    .await??;
    let signed = proof(state, &key, &token, "GET", json!({}))?;
    let healthy_response = get(state, Method::GET, PATH, Some(&auth), Some(&signed), "").await?;
    assert_eq!(value.as_deref(), Some("1"), "actual replay entry committed");
    assert_eq!(
        mutations, 1,
        "uncertain replay mutation must not be retried"
    );
    assert_eq!(failed_response?.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        healthy_response.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "lost replay acknowledgement must keep actual HTTP admission closed"
    );
    Ok(())
}

pub(super) fn proxy(
    listener: std::net::TcpListener,
    upstream: &redis::Client,
) -> anyhow::Result<(String, u32)> {
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
    let mut replay_key = None;
    let mut mutations = 0;
    loop {
        let arguments = match parser.parse_value(&mut socket) {
            Ok(redis::Value::Array(arguments)) => arguments,
            Ok(_) => anyhow::bail!("proxy expected command array"),
            Err(error) => {
                anyhow::ensure!(
                    error.is_connection_dropped(),
                    "driver did not close: {error}"
                );
                break;
            }
        };
        let Some(redis::Value::BulkString(command)) = arguments.first() else {
            anyhow::bail!("proxy expected command");
        };
        if command == b"SET" {
            let mut forwarded = redis::cmd("SET");
            for argument in arguments.iter().skip(1) {
                let redis::Value::BulkString(bytes) = argument else {
                    anyhow::bail!("proxy expected bytes");
                };
                forwarded.arg(bytes);
            }
            let reply: redis::Value = forwarded.query(&mut actual)?;
            anyhow::ensure!(reply == redis::Value::Okay, "replay was not committed");
            replay_key = Some(redis::from_redis_value::<String>(&arguments[1])?);
            mutations += 1;
            // Actual upstream SET succeeded; suppress all subsequent replies.
        } else if mutations == 0 {
            anyhow::ensure!(
                command == b"CLIENT" || command == b"PING",
                "unexpected setup"
            );
            socket.write_all(if command == b"PING" {
                b"+PONG\r\n"
            } else {
                b"+OK\r\n"
            })?;
        }
    }
    Ok((
        replay_key.ok_or_else(|| anyhow::anyhow!("no actual replay mutation"))?,
        mutations,
    ))
}
