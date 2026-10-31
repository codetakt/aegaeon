use super::*;
use crate::organizations::request_work::{Admission, MAX_REQUESTS};
use std::io::Write;
use std::time::{Duration, Instant};

#[test]
#[ignore = "requires isolated PostgreSQL and Redis; permanently closed admission child"]
fn shared_redis_organizations_csrf_generation_lost_ack_closes_http_admission() -> TestResult {
    let name = concat!(
        module_path!(),
        "::shared_redis_organizations_csrf_generation_lost_ack_closes_http_admission"
    );
    replay_completion::run_child(name.split_once("::").ok_or("crate prefix")?.1, || {
        exercise(false)
    })
}

#[test]
#[ignore = "requires isolated PostgreSQL and Redis; permanently closed admission child"]
fn shared_redis_organizations_csrf_consumption_lost_ack_closes_http_admission() -> TestResult {
    let name = concat!(
        module_path!(),
        "::shared_redis_organizations_csrf_consumption_lost_ack_closes_http_admission"
    );
    replay_completion::run_child(name.split_once("::").ok_or("crate prefix")?.1, || {
        exercise(true)
    })
}

async fn exercise(consume: bool) -> TestResult {
    let fixture = Fixture::with_identifier(IDENTIFIER).await?;
    let mut state = setup(&fixture).await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    state.device.local_auth_csrf_store = Arc::new(
        crate::device_authz::CsrfTokenStore::try_from_shared_store_env(
            "AEGAEON_TEST_REDIS_URL",
            "local-auth",
            &namespace,
        )?,
    );
    let result = request(&fixture, &state, consume).await;
    state.db_pool.close().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while Admission::available_for_test() != MAX_REQUESTS {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    fixture.cleanup(result).await
}

async fn page(
    state: &AppState,
    path: &str,
    token: Option<&str>,
) -> TestResult<(StatusCode, String)> {
    let request = if let Some(token) = token {
        Request::post(path)
            .header(header::ORIGIN, state.issuer.as_str())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                header::COOKIE,
                format!("__Host-aegaeon-organization-identity-csrf={token}"),
            )
            .body(Body::from(serde_urlencoded::to_string([
                ("csrf_token", token),
                ("action", "invalid"),
            ])?))?
    } else {
        Request::get(path).body(Body::empty())?
    };
    let mut request = request;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12543))));
    let response = crate::web::build_router(state.clone())
        .oneshot(request)
        .await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    Ok((
        response.status(),
        String::from_utf8(to_bytes(response.into_body(), 65536).await?.to_vec())?,
    ))
}

async fn request(fixture: &Fixture, state: &AppState, consume: bool) -> TestResult {
    let path = format!(
        "/organization-invitations/{}/{}/identity",
        fixture.organization.scope.domain_id,
        uuid::Uuid::new_v4()
    );
    let (status, html) = page(state, &path, None).await?;
    assert_eq!(status, StatusCode::OK, "normal form");
    let token = html
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .ok_or("CSRF field")?;
    Admission::drain_for_test().await?;
    let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let upstream = client.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("redis://{}/", listener.local_addr()?);
    let peer = std::thread::spawn(move || proxy(listener, &upstream, consume));
    let mut failed = state.clone();
    failed.device.local_auth_csrf_store = Arc::new(
        state
            .device
            .local_auth_csrf_store
            .with_redis_transport_for_tests(&url)?,
    );
    assert!(
        failed.require_subject_namespace().is_ok(),
        "reach actual CSRF store"
    );
    let failed_response = page(&failed, &path, consume.then_some(token)).await;
    let (key, mutations) = tokio::task::spawn_blocking(move || {
        peer.join()
            .map_err(|_| anyhow::anyhow!("CSRF proxy panicked"))?
    })
    .await??;
    let value = tokio::task::spawn_blocking(move || -> redis::RedisResult<Option<String>> {
        let mut connection = crate::redis_io::connect(&client)?;
        let value = redis::cmd("GET").arg(&key).query(&mut connection)?;
        redis::cmd("DEL").arg(&key).query::<i64>(&mut connection)?;
        Ok(value)
    })
    .await??;
    let healthy_response = page(state, &path, None).await?;
    assert_eq!(mutations, 1, "uncertain mutation must not be retried");
    assert_eq!(
        value.as_deref(),
        if consume { None } else { Some("1") },
        "actual CSRF mutation committed"
    );
    assert_eq!(failed_response?.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        healthy_response.0,
        StatusCode::SERVICE_UNAVAILABLE,
        "lost CSRF acknowledgement must keep actual HTTP admission closed"
    );
    Ok(())
}

fn proxy(
    listener: std::net::TcpListener,
    upstream: &redis::Client,
    consume: bool,
) -> anyhow::Result<(String, u32)> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                anyhow::ensure!(Instant::now() < deadline, "proxy accept deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e.into()),
        }
    };
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut actual = upstream.get_connection_with_timeout(Duration::from_secs(3))?;
    actual.set_read_timeout(Some(Duration::from_secs(3)))?;
    actual.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut parser = redis::Parser::new();
    let mut key = None;
    let mut mutations = 0;
    for _ in 0..64 {
        let arguments = match parser.parse_value(&mut socket) {
            Ok(redis::Value::Array(v)) => v,
            Ok(_) => anyhow::bail!("expected command array"),
            Err(e) => {
                anyhow::ensure!(e.is_connection_dropped(), "driver did not close: {e}");
                return Ok((
                    key.ok_or_else(|| anyhow::anyhow!("no actual CSRF mutation"))?,
                    mutations,
                ));
            }
        };
        let Some(redis::Value::BulkString(command)) = arguments.first() else {
            anyhow::bail!("command required")
        };
        if mutations > 0 {
            continue;
        }
        if command == b"CLIENT" || command == b"PING" {
            socket.write_all(if command == b"PING" {
                b"+PONG\r\n"
            } else {
                b"+OK\r\n"
            })?;
            continue;
        }
        anyhow::ensure!(
            (consume && (command == b"EVALSHA" || command == b"SCRIPT"))
                || (!consume && command == b"SET"),
            "unexpected CSRF command"
        );
        let mut forwarded = redis::cmd(std::str::from_utf8(command)?);
        for arg in arguments.iter().skip(1) {
            let redis::Value::BulkString(bytes) = arg else {
                anyhow::bail!("expected bytes")
            };
            forwarded.arg(bytes);
        }
        match forwarded.query::<redis::Value>(&mut actual) {
            Err(e) if e.kind() == redis::ErrorKind::NoScriptError => {
                socket.write_all(b"-NOSCRIPT missing\r\n")?
            }
            Err(e) => return Err(e.into()),
            Ok(redis::Value::BulkString(hash)) if command == b"SCRIPT" => {
                write!(socket, "${}\r\n", hash.len())?;
                socket.write_all(&hash)?;
                socket.write_all(b"\r\n")?;
            }
            Ok(value) => {
                anyhow::ensure!(
                    value
                        == if consume {
                            redis::Value::Int(1)
                        } else {
                            redis::Value::Okay
                        },
                    "CSRF mutation was not committed"
                );
                let index = if consume { 3 } else { 1 };
                key = Some(redis::from_redis_value::<String>(
                    arguments
                        .get(index)
                        .ok_or_else(|| anyhow::anyhow!("missing key"))?,
                )?);
                mutations += 1;
                // Upstream committed; lose its reply and all following replies.
            }
        }
    }
    anyhow::bail!("proxy command budget exceeded")
}
