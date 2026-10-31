use super::*;
use crate::organizations::witness::tests::caller_fixture::CallerFixture;
use std::io::Write;
use std::time::{Duration, Instant};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; live witness and browser-session read reply loss"]
async fn shared_redis_organizations_browser_session_loss_retains_actual_owner() -> anyhow::Result<()>
{
    let environment_id = uuid::Uuid::new_v4();
    let witness = CallerFixture::new(environment_id).await?;
    let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
    let prefix = format!("auth-session-epoch:{{{environment_id}}}");
    let result = exercise(&witness, &url, &prefix).await;
    let cleanup =
        clear_redis_auth_session_store_for_test(&url, &prefix).map_err(anyhow::Error::msg);
    let witness_cleanup = witness.finish().await;
    result.and(cleanup).and(witness_cleanup)
}

async fn exercise(witness: &CallerFixture, url: &str, prefix: &str) -> anyhow::Result<()> {
    let store = redis_auth_session_store_for_test(url, prefix).map_err(anyhow::Error::msg)?;
    let now = now_epoch_secs().map_err(anyhow::Error::msg)?;
    let first = witness.begin().await?;
    let sid = first
        .store_scope(async {
            store
                .try_create_async(
                    "session-owner".into(),
                    AuthSessionTimes::local(now),
                    None,
                    None,
                    None,
                )
                .await
                .map_err(anyhow::Error::msg)
        })
        .await??
        .ok_or_else(|| anyhow::anyhow!("session"))?;
    anyhow::ensure!(first.complete().await?.pending == 0);
    let next = witness.begin().await?;
    let actual = next
        .store_scope(store.try_get_async(sid.clone()))
        .await?
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("session"))?;
    anyhow::ensure!(actual.user_id == "session-owner");
    anyhow::ensure!(next.complete().await?.pending == 0);

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = format!("redis://{}/", listener.local_addr()?);
    let upstream = redis::Client::open(url)?;
    let peer = std::thread::spawn(move || lost_read_reply(listener, upstream));
    let failed = redis_auth_session_store_for_test(&address, prefix).map_err(anyhow::Error::msg)?;
    let work = witness.begin().await?;
    let closed = work.admission().closure_probe_for_test();
    let mut response = None;
    let scoped = work
        .store_scope(async {
            response = Some(failed.try_get_async(sid).await);
        })
        .await;
    let completion = work.complete().await;
    let reads = tokio::task::spawn_blocking(move || {
        peer.join().map_err(|_| anyhow::anyhow!("proxy panic"))?
    })
    .await??;
    anyhow::ensure!(reads == 1, "one actual upstream read, no retry");
    anyhow::ensure!(
        response.is_some_and(|r| r.is_err()),
        "lost read must refuse"
    );
    anyhow::ensure!(
        closed.is_closed(),
        "browser session worker must retain its witness owner"
    );
    anyhow::ensure!(scoped.is_err() && completion.is_err());
    anyhow::ensure!(witness.pending().await? == 1);
    Ok(())
}

fn lost_read_reply(
    listener: std::net::TcpListener,
    upstream: redis::Client,
) -> anyhow::Result<u32> {
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
    let mut reads = 0;
    loop {
        let arguments = match parser.parse_value(&mut socket) {
            Ok(redis::Value::Array(arguments)) => arguments,
            Ok(_) => anyhow::bail!("command array required"),
            Err(error) => {
                anyhow::ensure!(error.is_connection_dropped(), "driver close: {error}");
                break;
            }
        };
        let Some(redis::Value::BulkString(command)) = arguments.first() else {
            anyhow::bail!("command required")
        };
        if command == b"GET" {
            anyhow::ensure!(arguments.len() == 2);
            let redis::Value::BulkString(key) = &arguments[1] else {
                anyhow::bail!("key required")
            };
            let value: Option<String> = redis::cmd("GET").arg(key).query(&mut actual)?;
            anyhow::ensure!(value.is_some(), "actual session must exist");
            reads += 1;
            // The real read completed. Suppress its reply and any later barrier.
        } else if reads == 0 {
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
    Ok(reads)
}
