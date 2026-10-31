use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::io::Write;

fn store(url: &str, namespace: &str) -> anyhow::Result<Arc<VerificationRateLimiter>> {
    Ok(Arc::new(VerificationRateLimiter {
        backend: VerificationRateLimiterBackend::Redis(RedisVerificationRateLimiter::new(
            url,
            Arc::<str>::from(namespace),
        )?),
        max_attempts: 10,
        window: Duration::from_secs(60),
    }))
}

#[tokio::test]
#[ignore = "requires PostgreSQL witness and actual Redis; lost committed login rate-limit reply"]
async fn shared_redis_organizations_login_rate_limit_loss_retains_owner() -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4();
    let witness = CallerFixture::new(id).await?;
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let namespace = format!("organization-rate-epoch-{id}");
    let result = exercise(&witness, &url, &namespace).await;
    let mut connection =
        redis::Client::open(url)?.get_connection_with_timeout(Duration::from_secs(3))?;
    connection.set_read_timeout(Some(Duration::from_secs(3)))?;
    connection.set_write_timeout(Some(Duration::from_secs(3)))?;
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("rate-limit:v1:{{{namespace}}}:*"))
        .query(&mut connection)?;
    if !keys.is_empty() {
        redis::cmd("DEL").arg(keys).query::<i64>(&mut connection)?;
    }
    let cleanup = witness.finish().await;
    result.and(cleanup)
}

async fn exercise(witness: &CallerFixture, url: &str, namespace: &str) -> anyhow::Result<()> {
    let ordinary = store(url, namespace)?;
    let normal = witness.begin().await?;
    normal
        .store_scope(async {
            anyhow::ensure!(ordinary
                .clone()
                .try_check_async("first".into())
                .await
                .map_err(anyhow::Error::msg)?);
            anyhow::ensure!(ordinary
                .clone()
                .try_check_all_async(vec!["first".into(), "second".into()])
                .await
                .map_err(anyhow::Error::msg)?);
            anyhow::ensure!(ordinary
                .try_check_with_limit_async("third".into(), 2)
                .await
                .map_err(anyhow::Error::msg)?);
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    anyhow::ensure!(normal.complete().await?.pending == 0);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = format!("redis://{}/", listener.local_addr()?);
    let upstream = redis::Client::open(url)?;
    let peer = std::thread::spawn(move || proxy(listener, &upstream));
    let failed = store(&address, namespace)?;
    let work = witness.begin().await?;
    let closed = work.admission().closure_probe_for_test();
    let mut response = None;
    let scoped = work
        .store_scope(async {
            response = Some(failed.try_check_async("lost".into()).await);
        })
        .await;
    let completion = work.complete().await;
    let (key, mutations) = tokio::task::spawn_blocking(move || {
        peer.join().map_err(|_| anyhow::anyhow!("proxy panic"))?
    })
    .await??;
    let mut actual =
        redis::Client::open(url)?.get_connection_with_timeout(Duration::from_secs(3))?;
    actual.set_read_timeout(Some(Duration::from_secs(3)))?;
    actual.set_write_timeout(Some(Duration::from_secs(3)))?;
    let counter: i64 = redis::cmd("GET").arg(&key).query(&mut actual)?;
    anyhow::ensure!(
        mutations == 1 && counter == 1,
        "one actual mutation; no retry"
    );
    anyhow::ensure!(response.is_some_and(|v| v.is_err()));
    anyhow::ensure!(
        closed.is_closed(),
        "rate-limit worker must retain witness owner"
    );
    anyhow::ensure!(scoped.is_err() && completion.is_err());
    anyhow::ensure!(witness.pending().await? == 1);
    Ok(())
}

fn proxy(
    listener: std::net::TcpListener,
    upstream: &redis::Client,
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
                    key.ok_or_else(|| anyhow::anyhow!("no actual rate-limit mutation"))?,
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
            command == b"EVALSHA" || command == b"SCRIPT",
            "unexpected rate-limit command"
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
                    value == redis::Value::Int(1),
                    "rate-limit mutation was not committed"
                );
                let index = 3;
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
